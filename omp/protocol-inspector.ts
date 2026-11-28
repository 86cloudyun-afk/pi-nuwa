import { createHash, randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { computeBodyHash, computeTemplateFingerprint, type AutoFact } from "./autoexec";
import { computeKeyJaccard, extractJsonTopKeys, isAdminLikePath, isAdminLikeRole, isObjectResourcePath, type AuthDiffAnomalyKind } from "./auth-diff";
import type { CdpSession } from "./cdp-bridge";
import { checkScopeAndRisk, formatScopeBlockReason, isHostInScope } from "./scope";
import { getRoleHeadersMap, loadSessionVault, redactVaultSecrets, type SessionVault } from "./session-vault";
import { REDACTED_MARKER, redactTrafficBody, redactTrafficHeaders, redactTrafficUrl, TrafficRecorder } from "./traffic-workbench";
import type { Mode, ScopePolicy } from "./types";

export interface GraphQLTypeField { name: string; typeName: string; isList: boolean; isNonNull: boolean; args: Array<{ name: string; typeName: string }>; kind?: string; }
export interface GraphQLObjectSchema { name: string; kind: string; fields: GraphQLTypeField[]; enumValues?: string[]; }
export interface GraphQLSchemaSummary { introspectionEnabled: boolean; queryTypeName: string; mutationTypeName?: string; types: Record<string, GraphQLObjectSchema>; discoveredQueries: string[]; discoveredMutations: string[]; discoveredSuggestions: Record<string, string[]>; }
export interface GraphQLInspectOptions { headers?: Record<string, string>; timeoutMs?: number; fetchFn?: typeof fetch; mode?: Mode | string; root?: string; vault?: SessionVault; recorder?: TrafficRecorder; extraSecrets?: string[]; dictionary?: string[]; }
export interface GraphQLBatchOperation { alias: string; field: string; args?: Record<string, unknown>; selectionSet?: string; isMutation?: boolean; }
export interface GraphQLQuerySpec { name: string; query: string; variables?: Record<string, unknown>; expectedAdminOnly?: boolean; }
export interface GraphQLRoleDiffFinding { name: string; kind: AuthDiffAnomalyKind; severity: "high" | "medium"; summary: string; baselineRole: string; testedRole: string; similarity: number; exposedKeys: string[]; probes: Array<{ role: string; status: number; bodyHash: string; dataKeys: string[]; hasErrors: boolean; sampleSnippet: string }>; }
export interface GraphQLAuthDiffOptions { roles?: string[]; extraRoleHeaders?: Record<string, Record<string, string>>; adminRoles?: string[]; timeoutMs?: number; fetchFn?: typeof fetch; mode?: Mode | string; recorder?: TrafficRecorder; extraSecrets?: string[]; }
export interface GraphQLAuthDiffResult { ok: boolean; endpointUrl: string; blockedByScope: boolean; blockReason?: string; testedQueries: string[]; findings: GraphQLRoleDiffFinding[]; fact: AutoFact | null; }

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonRecord : undefined;
}

function uniqueStrings(values: readonly (string | undefined | null)[]): string[] {
	const out = new Set<string>();
	for (const value of values) {
		const text = typeof value === "string" ? value.trim() : "";
		if (text) out.add(text);
	}
	return [...out];
}

function escapeRegExp(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeGraphQLPayload(payload: unknown): unknown {
	if (!(payload instanceof Uint8Array)) return payload;
	try { return JSON.parse(gunzipSync(payload).toString("utf8")); }
	catch {
		try { return JSON.parse(Buffer.from(payload).toString("utf8")); }
		catch { return payload; }
	}
}

function checkProtocolTargetScope(rawUrl: string, method: string, scope: ScopePolicy, mode?: Mode | string, label?: string): { ok: true; parsed: URL } | { ok: false; reason: string } {
	let parsed: URL;
	try { parsed = new URL(rawUrl); }
	catch { return { ok: false, reason: `${label ? `${label}: ` : ""}invalid URL` }; }
	if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) {
		return { ok: false, reason: `${label ? `${label}: ` : ""}unsupported protocol ${parsed.protocol}` };
	}
	const hostCheck = isHostInScope(parsed.hostname, scope);
	if (!hostCheck.ok) return { ok: false, reason: `${label ? `${label}: ` : ""}${hostCheck.reason ?? "host out of scope"}` };
	const block = checkScopeAndRisk(`${method.toUpperCase()} ${parsed.href}`, scope, mode ?? "audit", { layer: "egress-proxy" });
	if (block) return { ok: false, reason: `${label ? `${label}: ` : ""}${formatScopeBlockReason(block.layer ?? "egress-proxy", block.reason)}` };
	return { ok: true, parsed };
}

function collectSecretsFromHeaders(headers?: Record<string, string>): string[] {
	const out = new Set<string>();
	const add = (raw?: string): void => {
		const value = typeof raw === "string" ? raw.trim() : "";
		if (value.length >= 3) out.add(value);
	};
	for (const [rawName, rawValue] of Object.entries(headers ?? {})) {
		const name = rawName.toLowerCase();
		const value = String(rawValue ?? "");
		if (!value) continue;
		if (name === "cookie") {
			add(value);
			for (const part of value.split(";")) {
				const eq = part.indexOf("=");
				if (eq >= 0) add(part.slice(eq + 1));
			}
			continue;
		}
		if (name === "authorization") {
			add(value);
			const bearer = /^Bearer\s+(.+)$/i.exec(value);
			if (bearer?.[1]) add(bearer[1]);
			const basic = /^Basic\s+(.+)$/i.exec(value);
			if (basic?.[1]) {
				add(basic[1]);
				try {
					const decoded = Buffer.from(basic[1], "base64").toString("utf8");
					add(decoded);
					const colon = decoded.indexOf(":");
					if (colon >= 0) { add(decoded.slice(0, colon)); add(decoded.slice(colon + 1)); }
				} catch { /* best effort */ }
			}
			continue;
		}
		if (/(api[-_]?key|token|secret|password|passwd|auth|session|csrf|xsrf|signature|credential)/i.test(name)) add(value);
	}
	return [...out];
}

function scrubProtocolText(text: string, extraSecrets?: readonly string[], rootOrVault?: string | SessionVault): string {
	let out = text;
	const secrets = uniqueStrings([...(extraSecrets ?? [])]).filter((s) => s.length >= 3).sort((a, b) => b.length - a.length);
	for (const secret of secrets) {
		const variants = new Set<string>([secret]);
		try { const encoded = encodeURIComponent(secret); if (encoded !== secret) variants.add(encoded); } catch { /* ignore */ }
		for (const variant of variants) out = out.split(variant).join(REDACTED_MARKER);
	}
	if (rootOrVault !== undefined) {
		try { out = redactVaultSecrets(out, rootOrVault); } catch { /* best effort */ }
	}
	return out;
}

function resolveRoleHeadersBundle(rootOrVault: string | SessionVault, opts?: { roles?: string[]; extraRoleHeaders?: Record<string, Record<string, string>>; adminRoles?: string[]; }): {
	roleOrder: string[];
	roleHeaders: Map<string, Record<string, string>>;
	extraSecrets: string[];
	rootDir?: string;
	vaultRef?: SessionVault;
} {
	const vault = typeof rootOrVault === "string" ? loadSessionVault(rootOrVault) : rootOrVault;
	const rootDir = typeof rootOrVault === "string" ? resolve(rootOrVault) : undefined;
	const roleSet = new Set<string>(["anon"]);
	for (const role of opts?.roles ?? []) roleSet.add(role);
	for (const role of Object.keys(vault.roles ?? {})) roleSet.add(role);
	for (const role of Object.keys(opts?.extraRoleHeaders ?? {})) roleSet.add(role);
	const roleOrder = [...roleSet];
	const roleHeaders = new Map<string, Record<string, string>>();
	const extraSecrets = new Set<string>();
	for (const role of roleOrder) {
		const fromVault = role === "anon" ? {} : (getRoleHeadersMap(vault, role) ?? {});
		const extra = role === "anon" ? {} : (opts?.extraRoleHeaders?.[role] ?? {});
		const merged: Record<string, string> = { ...fromVault, ...extra };
		roleHeaders.set(role, merged);
		for (const secret of collectSecretsFromHeaders(merged)) extraSecrets.add(secret);
	}
	return { roleOrder, roleHeaders, extraSecrets: [...extraSecrets], rootDir, vaultRef: vault };
}

function clipSafeSnippet(raw: string, opts?: { root?: string; vault?: SessionVault; extraSecrets?: string[]; maxChars?: number }): string {
	const maxChars = Math.max(40, opts?.maxChars ?? 500);
	const redacted = redactTrafficBody(raw, { root: opts?.root, vault: opts?.vault, extraSecrets: opts?.extraSecrets, maxChars }) ?? "";
	return redacted.length > maxChars ? `${redacted.slice(0, maxChars)}…` : redacted;
}

function headersToRecord(headers: Headers | Record<string, string> | undefined): Record<string, string> {
	if (!headers) return {};
	if (headers instanceof Headers) {
		const out: Record<string, string> = {};
		headers.forEach((value, key) => { out[key] = value; });
		return out;
	}
	const out: Record<string, string> = {};
	for (const [key, value] of Object.entries(headers)) out[key] = String(value);
	return out;
}

function recordProtocolTraffic(recorder: TrafficRecorder | undefined, input: {
	method: string; url: string; requestHeaders?: Record<string, string>; requestBody?: string; status: number;
	responseHeaders?: Record<string, string>; responseBody?: string; durationMs?: number; tags?: string[]; role?: string; note?: string;
}): void {
	if (!recorder) return;
	const allHeaders = { ...(input.requestHeaders ?? {}), ...(input.responseHeaders ?? {}) };
	const secrets = collectSecretsFromHeaders(allHeaders);
	for (const secret of secrets) recorder.registerTransientSecret(secret);
	const extraSecrets = uniqueStrings([...secrets, ...collectSecretsFromHeaders(input.responseHeaders)]);
	recorder.record({
		method: input.method,
		url: redactTrafficUrl(input.url, { extraSecrets }),
		requestHeaders: redactTrafficHeaders(input.requestHeaders, { extraSecrets }),
		requestBody: redactTrafficBody(input.requestBody, { extraSecrets }),
		status: input.status,
		responseHeaders: redactTrafficHeaders(input.responseHeaders, { extraSecrets }),
		responseBody: redactTrafficBody(input.responseBody, { extraSecrets }),
		durationMs: input.durationMs,
		tags: input.tags,
		role: input.role,
		note: input.note ? scrubProtocolText(input.note, extraSecrets) : undefined,
	});
}

function assertGraphQLIdentifier(name: string, label: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`Invalid GraphQL ${label}: ${name}`);
	return name;
}

function serializeGraphQLValue(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string") return JSON.stringify(value);
	if (typeof value === "number" && Number.isFinite(value)) return String(value);
	if (typeof value === "boolean") return value ? "true" : "false";
	if (Array.isArray(value)) return `[${value.map(serializeGraphQLValue).join(", ")}]`;
	const rec = asRecord(value);
	if (rec) return `{${Object.entries(rec).map(([key, item]) => `${assertGraphQLIdentifier(key, "argument key")}: ${serializeGraphQLValue(item)}`).join(", ")}}`;
	throw new Error("Unsupported GraphQL argument value");
}

function serializeGraphQLArgs(args: Record<string, unknown>): string {
	const entries = Object.entries(args);
	if (!entries.length) return "";
	return `(${entries.map(([key, value]) => `${assertGraphQLIdentifier(key, "argument")}: ${serializeGraphQLValue(value)}`).join(", ")})`;
}

function sanitizeSelectionSet(input?: string): string | undefined {
	if (!input) return undefined;
	const text = input.trim();
	if (!text) return undefined;
	if (!/^[A-Za-z0-9_{}\s:(),!\[\]$".-]+$/.test(text)) throw new Error("Unsafe GraphQL selection set");
	return text;
}

function unwrapTypeRef(ref: unknown): { typeName: string; isList: boolean; isNonNull: boolean; kind?: string } {
	let current = asRecord(ref);
	let isList = false;
	let isNonNull = false;
	let typeName = "Unknown";
	let kind: string | undefined;
	for (let depth = 0; current && depth < 12; depth += 1) {
		const currentKind = typeof current.kind === "string" ? current.kind : undefined;
		if (currentKind === "NON_NULL") isNonNull = true;
		if (currentKind === "LIST") isList = true;
		if (typeof current.name === "string" && current.name) { typeName = current.name; kind = currentKind; }
		current = asRecord(current.ofType);
	}
	return kind ? { typeName, isList, isNonNull, kind } : { typeName, isList, isNonNull };
}

function parseGraphQLField(raw: unknown): GraphQLTypeField | undefined {
	const field = asRecord(raw);
	const name = typeof field?.name === "string" ? field.name : undefined;
	if (!field || !name) return undefined;
	const type = unwrapTypeRef(field.type);
	const argsRaw = Array.isArray(field.args) ? field.args : [];
	const args = argsRaw.map((arg) => {
		const rec = asRecord(arg);
		const argName = typeof rec?.name === "string" ? rec.name : undefined;
		if (!argName) return undefined;
		return { name: argName, typeName: unwrapTypeRef(rec?.type).typeName };
	}).filter((arg): arg is { name: string; typeName: string } => Boolean(arg));
	return { name, typeName: type.typeName, isList: type.isList, isNonNull: type.isNonNull, args, ...(type.kind ? { kind: type.kind } : {}) };
}

export function parseGraphQLIntrospection(payload: unknown): GraphQLSchemaSummary {
	const root = asRecord(normalizeGraphQLPayload(payload));
	const data = asRecord(root?.data) ?? root;
	const schema = asRecord(data?.__schema) ?? asRecord(root?.__schema);
	if (!schema) return { introspectionEnabled: false, queryTypeName: "Query", types: {}, discoveredQueries: [], discoveredMutations: [], discoveredSuggestions: {} };
	const queryTypeName = typeof asRecord(schema.queryType)?.name === "string" ? String(asRecord(schema.queryType)?.name) : "Query";
	const mutationNameRaw = asRecord(schema.mutationType)?.name;
	const mutationTypeName = typeof mutationNameRaw === "string" && mutationNameRaw ? mutationNameRaw : undefined;
	const types: Record<string, GraphQLObjectSchema> = {};
	for (const rawType of Array.isArray(schema.types) ? schema.types : []) {
		const rec = asRecord(rawType);
		const name = typeof rec?.name === "string" ? rec.name : undefined;
		if (!rec || !name) continue;
		const fields = (Array.isArray(rec.fields) ? rec.fields : []).map(parseGraphQLField).filter((field): field is GraphQLTypeField => Boolean(field));
		const enumValues = (Array.isArray(rec.enumValues) ? rec.enumValues : []).map((item) => asRecord(item)?.name).filter((value): value is string => typeof value === "string");
		types[name] = { name, kind: typeof rec.kind === "string" ? rec.kind : "OBJECT", fields, ...(enumValues.length ? { enumValues } : {}) };
	}
	const discoveredQueries = (types[queryTypeName]?.fields ?? []).map((field) => field.name);
	const discoveredMutations = mutationTypeName ? (types[mutationTypeName]?.fields ?? []).map((field) => field.name) : [];
	return { introspectionEnabled: true, queryTypeName, ...(mutationTypeName ? { mutationTypeName } : {}), types, discoveredQueries, discoveredMutations, discoveredSuggestions: {} };
}

function collectErrorMessages(value: unknown, out: string[] = [], depth = 0): string[] {
	if (depth > 4 || out.length > 50) return out;
	if (typeof value === "string") { out.push(value); return out; }
	if (Array.isArray(value)) { for (const item of value) collectErrorMessages(item, out, depth + 1); return out; }
	const rec = asRecord(value);
	if (!rec) return out;
	if (typeof rec.message === "string") out.push(rec.message);
	for (const [key, item] of Object.entries(rec)) if (key !== "message" && key !== "locations" && key !== "path") collectErrorMessages(item, out, depth + 1);
	return out;
}

export function parseGraphQLSuggestionsFromErrors(errors: unknown): string[] {
	const suggestions = new Set<string>();
	for (const message of collectErrorMessages(errors)) {
		const match = /did you mean/i.exec(message);
		if (!match || match.index === undefined) continue;
		const tail = message.slice(match.index + match[0].length);
		const regex = /["']([A-Za-z_][A-Za-z0-9_]*)["']/g;
		for (let item = regex.exec(tail); item; item = regex.exec(tail)) {
			if (item[1]) suggestions.add(item[1]);
		}
	}
	return [...suggestions];
}

export function buildGraphQLAliasQuery(ops: readonly GraphQLBatchOperation[], operationName?: string): string {
	if (!ops.length) throw new Error("At least one GraphQL batch operation is required");
	const mutation = ops[0]?.isMutation === true;
	if (ops.some((op) => Boolean(op.isMutation) !== mutation)) throw new Error("Cannot mix query and mutation operations in one batch");
	const body = ops.map((op) => {
		const alias = assertGraphQLIdentifier(op.alias, "alias");
		const field = assertGraphQLIdentifier(op.field, "field");
		const args = op.args ? serializeGraphQLArgs(op.args) : "";
		const selectionSet = sanitizeSelectionSet(op.selectionSet);
		return `${alias}: ${field}${args}${selectionSet ? ` { ${selectionSet} }` : ""}`;
	}).join(" ");
	const opName = operationName ? ` ${assertGraphQLIdentifier(operationName, "operation name")}` : "";
	return `${mutation ? "mutation" : "query"}${opName} { ${body} }`;
}

export function buildGraphQLBatchPayload(queries: ReadonlyArray<{ query: string; variables?: Record<string, unknown>; operationName?: string }>): Array<{ query: string; variables?: Record<string, unknown>; operationName?: string }> {
	return queries.map((item) => {
		if (!item.query.trim()) throw new Error("GraphQL query cannot be empty");
		return {
			query: item.query,
			...(item.variables !== undefined ? { variables: item.variables } : {}),
			...(item.operationName ? { operationName: assertGraphQLIdentifier(item.operationName, "operation name") } : {}),
		};
	});
}

const GRAPHQL_INTROSPECTION_QUERY = `query NuwaIntrospection { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } enumValues { name } } } }`;

const DEFAULT_GRAPHQL_FIELD_DICTIONARY = [
	"user", "users", "me", "viewer", "account", "accounts", "admin", "adminSettings", "settings", "config", "login", "register",
	"node", "nodes", "search", "products", "orders", "posts", "comments", "messages", "notifications", "auditLogs", "apiKey", "apiKeys",
	"roles", "permissions", "team", "teams", "organization", "organizations", "billing", "invoice", "invoices", "session", "sessions",
	"file", "files", "upload", "health", "version", "ping", "status", "profile", "profiles", "customer", "customers", "transaction",
	"transactions", "payment", "payments", "todo", "todos", "item", "items", "list", "lists", "project", "projects", "task", "tasks",
	"report", "reports", "log", "logs", "event", "events", "device", "devices", "token", "tokens", "secret", "secrets", "flag", "flags",
];

function emptyGraphQLSummary(): GraphQLSchemaSummary {
	return { introspectionEnabled: false, queryTypeName: "Query", types: {}, discoveredQueries: [], discoveredMutations: [], discoveredSuggestions: {} };
}

interface GraphQLHttpResult { status: number; body: string; json: unknown; durationMs: number; error?: string; }

async function graphqlHttpPost(endpointUrl: string, payload: unknown, headers: Record<string, string>, opts: {
	timeoutMs?: number; fetchFn?: typeof fetch; recorder?: TrafficRecorder; role?: string; extraSecrets?: string[]; note?: string;
}): Promise<GraphQLHttpResult> {
	const body = JSON.stringify(payload);
	const requestFingerprint = createHash("sha256").update(gzipSync(body)).digest("hex").slice(0, 12);
	const started = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), Math.max(1000, opts.timeoutMs ?? 8000));
	try {
		const response = await (opts.fetchFn ?? fetch)(endpointUrl, {
			method: "POST",
			headers: { "content-type": "application/json", accept: "application/json", ...headers },
			body,
			signal: controller.signal,
		});
		const text = await response.text();
		let json: unknown;
		try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
		const durationMs = Date.now() - started;
		const responseHeaders = headersToRecord(response.headers);
		const templateFingerprint = computeTemplateFingerprint(text, endpointUrl);
		recordProtocolTraffic(opts.recorder, {
			method: "POST", url: endpointUrl, requestHeaders: headers, requestBody: body, status: response.status,
			responseHeaders, responseBody: text, durationMs, tags: ["graphql", `req:${requestFingerprint}`, `tpl:${templateFingerprint}`],
			role: opts.role, note: opts.note,
		});
		return { status: response.status, body: text, json, durationMs };
	} catch (error) {
		const durationMs = Date.now() - started;
		recordProtocolTraffic(opts.recorder, {
			method: "POST", url: endpointUrl, requestHeaders: headers, requestBody: body, status: 0, durationMs,
			tags: ["graphql", "error", `req:${requestFingerprint}`], role: opts.role, note: opts.note,
		});
		return { status: 0, body: "", json: undefined, durationMs, error: error instanceof Error ? error.message : String(error) };
	} finally {
		clearTimeout(timer);
	}
}

export async function inspectGraphQLSchema(endpointUrl: string, scope: ScopePolicy, opts: GraphQLInspectOptions = {}): Promise<GraphQLSchemaSummary & { ok: boolean; blockedByScope: boolean; blockReason?: string; error?: string }> {
	const scopeCheck = checkProtocolTargetScope(endpointUrl, "POST", scope, opts.mode, "graphql-introspection");
	if (!scopeCheck.ok) return { ...emptyGraphQLSummary(), ok: false, blockedByScope: true, blockReason: scopeCheck.reason };
	const headers: Record<string, string> = { ...(opts.headers ?? {}) };
	const extraSecrets = uniqueStrings([...(opts.extraSecrets ?? []), ...collectSecretsFromHeaders(headers)]);
	const httpOpts = { timeoutMs: opts.timeoutMs, fetchFn: opts.fetchFn, recorder: opts.recorder, extraSecrets, note: "graphql introspection" };
	const intro = await graphqlHttpPost(endpointUrl, { query: GRAPHQL_INTROSPECTION_QUERY }, headers, httpOpts);
	if (intro.json) {
		const parsed = parseGraphQLIntrospection(intro.json);
		if (parsed.introspectionEnabled) return { ...parsed, ok: true, blockedByScope: false };
	}
	const suggestions: Record<string, string[]> = {};
	const discoveredQueries = new Set<string>();
	const discoveredMutations = new Set<string>();
	const probeSuffix = `__nuwa_probe_${randomBytes(4).toString("hex")}`;
	const dictionary = uniqueStrings([...(opts.dictionary ?? []), ...DEFAULT_GRAPHQL_FIELD_DICTIONARY]).slice(0, opts.dictionary?.length ? Math.min(opts.dictionary.length, 96) : 48);
	const rootQueryError = await graphqlHttpPost(endpointUrl, { query: `query ${makeProbeOperationName("NuwaQueryProbe")} { ${probeSuffix} }` }, headers, { ...httpOpts, note: "graphql root query suggestion probe" });
	for (const suggestion of parseGraphQLSuggestionsFromErrors(asRecord(rootQueryError.json)?.errors)) discoveredQueries.add(suggestion);
	if (discoveredQueries.size) suggestions.Query = [...discoveredQueries];
	const rootMutationError = await graphqlHttpPost(endpointUrl, { query: `mutation ${makeProbeOperationName("NuwaMutationProbe")} { ${probeSuffix} }` }, headers, { ...httpOpts, note: "graphql root mutation suggestion probe" });
	for (const suggestion of parseGraphQLSuggestionsFromErrors(asRecord(rootMutationError.json)?.errors)) discoveredMutations.add(suggestion);
	if (discoveredMutations.size) suggestions.Mutation = [...discoveredMutations];
	for (const field of dictionary) {
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(field)) continue;
		const probe = await graphqlHttpPost(endpointUrl, { query: `query ${makeProbeOperationName("NuwaFieldProbe")} { ${field} { __typename } }` }, headers, { ...httpOpts, note: `graphql field probe ${field}` });
		const data = asRecord(asRecord(probe.json)?.data);
		const fieldSuggestions = parseGraphQLSuggestionsFromErrors(asRecord(probe.json)?.errors);
		if (fieldSuggestions.length) {
			suggestions[field] = uniqueStrings([...(suggestions[field] ?? []), ...fieldSuggestions]);
			for (const suggestion of fieldSuggestions) discoveredQueries.add(suggestion);
		}
		if (data && Object.prototype.hasOwnProperty.call(data, field)) {
			discoveredQueries.add(field);
			const value = data[field];
			if (value !== null && typeof value === "object") {
				const sub = await graphqlHttpPost(endpointUrl, { query: `query ${makeProbeOperationName("NuwaSubFieldProbe")} { ${field} { ${probeSuffix} } }` }, headers, { ...httpOpts, note: `graphql subfield probe ${field}` });
				const subSuggestions = parseGraphQLSuggestionsFromErrors(asRecord(sub.json)?.errors);
				if (subSuggestions.length) suggestions[field] = uniqueStrings([...(suggestions[field] ?? []), ...subSuggestions]);
			}
		}
	}
	const types: Record<string, GraphQLObjectSchema> = {
		Query: {
			name: "Query",
			kind: "OBJECT",
			fields: [...discoveredQueries].map((name) => ({ name, typeName: "Unknown", isList: false, isNonNull: false, args: [] })),
		},
	};
	const mutationTypeName = discoveredMutations.size ? "Mutation" : undefined;
	if (mutationTypeName) {
		types.Mutation = { name: "Mutation", kind: "OBJECT", fields: [...discoveredMutations].map((name) => ({ name, typeName: "Unknown", isList: false, isNonNull: false, args: [] })) };
	}
	const summary: GraphQLSchemaSummary = {
		introspectionEnabled: false,
		queryTypeName: "Query",
		...(mutationTypeName ? { mutationTypeName } : {}),
		types,
		discoveredQueries: [...discoveredQueries],
		discoveredMutations: [...discoveredMutations],
		discoveredSuggestions: suggestions,
	};
	const ok = discoveredQueries.size > 0 || discoveredMutations.size > 0 || Object.keys(suggestions).length > 0;
	return { ...summary, ok, blockedByScope: false, ...(intro.error ? { error: intro.error } : {}) };
}

function makeProbeOperationName(prefix: string): string {
	return `${prefix}_${randomUUID().replace(/-/g, "").slice(0, 8)}`;
}

interface GraphQLProbeResult {
	role: string;
	status: number;
	bodyHash: string;
	dataKeys: string[];
	hasErrors: boolean;
	sampleSnippet: string;
	dataMap: Map<string, unknown>;
}

function flattenGraphQLData(value: unknown, prefix: string, out: Map<string, unknown>, depth = 0): void {
	if (depth > 6 || out.size > 400) return;
	if (Array.isArray(value)) {
		for (const item of value.slice(0, 3)) flattenGraphQLData(item, `${prefix}[]`, out, depth + 1);
		return;
	}
	const rec = asRecord(value);
	if (!rec) return;
	for (const [key, item] of Object.entries(rec)) {
		const path = prefix ? `${prefix}.${key}` : key;
		out.set(path, item);
		if (item !== null && typeof item === "object") flattenGraphQLData(item, path, out, depth + 1);
	}
}

function hasDifferingObjectLeaf(a: GraphQLProbeResult, b: GraphQLProbeResult): boolean {
	for (const [path, valueA] of a.dataMap) {
		if (!/(^|\.)(id|userId|accountId|ownerId|email|orderId|tenantId)($|\.|\[\])/i.test(path)) continue;
		if (!b.dataMap.has(path)) continue;
		const valueB = b.dataMap.get(path);
		if (valueA !== null && typeof valueA === "object") continue;
		if (valueB !== null && typeof valueB === "object") continue;
		if (JSON.stringify(valueA) !== JSON.stringify(valueB)) return true;
	}
	return false;
}

export async function runGraphQLNestedAuthDiff(endpointUrl: string, queries: readonly GraphQLQuerySpec[], rootOrVault: string | SessionVault, scope: ScopePolicy, opts: GraphQLAuthDiffOptions = {}): Promise<GraphQLAuthDiffResult> {
	const scopeCheck = checkProtocolTargetScope(endpointUrl, "POST", scope, opts.mode, "graphql-auth-diff");
	const base = { ok: false, endpointUrl, blockedByScope: false, testedQueries: [] as string[], findings: [] as GraphQLRoleDiffFinding[], fact: null as AutoFact | null };
	if (!scopeCheck.ok) return { ...base, blockedByScope: true, blockReason: scopeCheck.reason };
	const bundle = resolveRoleHeadersBundle(rootOrVault, { roles: opts.roles, extraRoleHeaders: opts.extraRoleHeaders, adminRoles: opts.adminRoles });
	const extraSecrets = uniqueStrings([...(opts.extraSecrets ?? []), ...bundle.extraSecrets]);
	const findings: GraphQLRoleDiffFinding[] = [];
	const findingKeys = new Set<string>();
	const testedQueries: string[] = [];
	const addFinding = (finding: GraphQLRoleDiffFinding): void => {
		const key = `${finding.kind}:${finding.name}:${finding.testedRole}`;
		if (!findingKeys.has(key)) { findingKeys.add(key); findings.push(finding); }
	};
	for (const spec of queries) {
		testedQueries.push(spec.name);
		const probes: GraphQLProbeResult[] = [];
		for (const role of bundle.roleOrder) {
			const roleHeaders = bundle.roleHeaders.get(role) ?? {};
			const response = await graphqlHttpPost(endpointUrl, { query: spec.query, variables: spec.variables, operationName: spec.name }, roleHeaders, {
				timeoutMs: opts.timeoutMs, fetchFn: opts.fetchFn, recorder: opts.recorder, role, extraSecrets, note: `graphql auth diff ${spec.name}`,
			});
			const parsed = asRecord(response.json);
			const data = parsed?.data;
			const hasErrors = Array.isArray(parsed?.errors) && parsed.errors.length > 0;
			const dataMap = new Map<string, unknown>();
			if (data !== undefined && data !== null) flattenGraphQLData(data, "data", dataMap);
			extractJsonTopKeys(response.body);
			probes.push({
				role,
				status: response.status,
				bodyHash: computeBodyHash(response.body).bodyHash,
				dataKeys: [...dataMap.keys()].sort(),
				hasErrors,
				sampleSnippet: clipSafeSnippet(response.body, { extraSecrets, maxChars: 420 }),
				dataMap,
			});
		}
		const byRole = new Map(probes.map((probe) => [probe.role, probe] as const));
		const usable = probes.filter((probe) => probe.status >= 200 && probe.status < 400 && probe.dataKeys.length > 0 && !probe.hasErrors);
		if (!usable.length) continue;
		const adminRoles = bundle.roleOrder.filter((role) => isAdminLikeRole(role, opts.adminRoles));
		const adminProbe = adminRoles.map((role) => byRole.get(role)).find((probe): probe is GraphQLProbeResult => Boolean(probe && usable.includes(probe)));
		const baseline = adminProbe ?? usable[0]!;
		const baselineKeys = new Set(baseline.dataKeys);
		const similarityToBaseline = (keys: string[]): number => computeKeyJaccard([...baselineKeys], keys);
		const exposedFor = (keys: string[]): string[] => keys.filter((key) => !baselineKeys.has(key)).slice(0, 40);
		const anonProbe = byRole.get("anon");
		if (anonProbe && usable.includes(anonProbe) && baseline.role !== "anon") {
			const similarity = similarityToBaseline(anonProbe.dataKeys);
			const sensitiveBaseline = baseline.dataKeys.some((key) => /admin|secret|apiKey|role|permission|token/i.test(key));
			if (similarity >= 0.25 || spec.expectedAdminOnly || isAdminLikePath(spec.name) || sensitiveBaseline) {
				addFinding({
					name: spec.name, kind: "unauth_access", severity: spec.expectedAdminOnly || isAdminLikePath(spec.name) ? "high" : "medium",
					summary: scrubProtocolText(`Anonymous role returned ${anonProbe.dataKeys.length} data key(s) for ${spec.name}`, extraSecrets, rootOrVault),
					baselineRole: baseline.role, testedRole: "anon", similarity, exposedKeys: anonProbe.dataKeys.slice(0, 40),
					probes: probes.map((probe) => ({ role: probe.role, status: probe.status, bodyHash: probe.bodyHash, dataKeys: probe.dataKeys, hasErrors: probe.hasErrors, sampleSnippet: probe.sampleSnippet })),
				});
			}
		}
		if (adminProbe) {
			for (const probe of usable) {
				if (probe.role === adminProbe.role || probe.role === "anon" || isAdminLikeRole(probe.role, opts.adminRoles)) continue;
				const similarity = similarityToBaseline(probe.dataKeys);
				const exposed = exposedFor(probe.dataKeys);
				if ((similarity >= 0.6 && exposed.length > 0) || (spec.expectedAdminOnly && similarity >= 0.2) || (isAdminLikePath(spec.name) && similarity >= 0.3)) {
					addFinding({
						name: spec.name, kind: "vertical_bfla", severity: spec.expectedAdminOnly || isAdminLikePath(spec.name) ? "high" : "medium",
						summary: scrubProtocolText(`Role ${probe.role} reached admin-like data for ${spec.name}`, extraSecrets, rootOrVault),
						baselineRole: adminProbe.role, testedRole: probe.role, similarity, exposedKeys: exposed,
						probes: probes.map((item) => ({ role: item.role, status: item.status, bodyHash: item.bodyHash, dataKeys: item.dataKeys, hasErrors: item.hasErrors, sampleSnippet: item.sampleSnippet })),
					});
				}
			}
		}
		const nonAdminUsable = usable.filter((probe) => probe.role !== "anon" && !isAdminLikeRole(probe.role, opts.adminRoles));
		for (let i = 0; i < nonAdminUsable.length; i += 1) {
			for (let j = i + 1; j < nonAdminUsable.length; j += 1) {
				const left = nonAdminUsable[i]!;
				const right = nonAdminUsable[j]!;
				const similarity = computeKeyJaccard(left.dataKeys, right.dataKeys);
				if (similarity < 0.8) continue;
				const objectLike = isObjectResourcePath(spec.name) || /(^|[._])(id|userId|accountId|ownerId|email|orderId|tenantId)($|[._])/i.test(left.dataKeys.join(" "));
				if (!objectLike || !hasDifferingObjectLeaf(left, right)) continue;
				addFinding({
					name: spec.name, kind: "horizontal_bola", severity: "medium",
					summary: scrubProtocolText(`Roles ${left.role} and ${right.role} returned overlapping object data for ${spec.name}`, extraSecrets, rootOrVault),
					baselineRole: left.role, testedRole: right.role, similarity, exposedKeys: left.dataKeys.filter((key) => right.dataKeys.includes(key)).slice(0, 40),
					probes: probes.map((probe) => ({ role: probe.role, status: probe.status, bodyHash: probe.bodyHash, dataKeys: probe.dataKeys, hasErrors: probe.hasErrors, sampleSnippet: probe.sampleSnippet })),
				});
			}
		}
	}
	const fact = findings.length ? buildGraphQLAuthDiffFact(endpointUrl, findings, extraSecrets, rootOrVault) : null;
	return { ok: true, endpointUrl, blockedByScope: false, testedQueries, findings, fact };
}

function buildGraphQLAuthDiffFact(endpointUrl: string, findings: GraphQLRoleDiffFinding[], extraSecrets: string[], rootOrVault: string | SessionVault): AutoFact {
	const root = typeof rootOrVault === "string" ? rootOrVault : undefined;
	const vault = typeof rootOrVault === "string" ? undefined : rootOrVault;
	const detail = scrubProtocolText(findings.map((finding) => `[${finding.kind}] ${finding.name} (${finding.testedRole} vs ${finding.baselineRole}) ${finding.summary}`).join("\n"), extraSecrets, rootOrVault);
	const output = scrubProtocolText(findings.map((finding) => `${finding.name}: ${finding.probes.map((probe) => `${probe.role}=${probe.status} keys=${probe.dataKeys.length} errors=${probe.hasErrors}`).join(", ")}`).join("\n"), extraSecrets, rootOrVault);
	return {
		kind: "vuln",
		title: `GraphQL auth diff: ${findings.length} finding(s)`,
		detail,
		command: `POST ${redactTrafficUrl(endpointUrl, { root, vault, extraSecrets })}`,
		output,
	};
}
// === Part 2：WebSocket 双向帧审计模块 ===

export interface CdpWebSocketFrameEvent {
	requestId: string;
	url: string;
	direction: "sent" | "received";
	opcode: number;
	payloadData: string;
	timestamp: number;
	parsedJson?: unknown;
}

export interface WebSocketAuditFinding {
	kind: "cross_tenant_push" | "unauth_ws_subscription" | "sensitive_frame_leak";
	severity: "high" | "medium";
	url: string;
	role: string;
	summary: string;
	sampleFrame: string;
}

export interface WsActiveAuditSpec {
	wsUrl: string;
	role: string;
	headers?: Record<string, string>;
	subscribeMessages: Array<string | Record<string, unknown>>;
	expectedTenantMarker?: string;
	foreignTenantMarkers?: string[];
	timeoutMs?: number;
	settleMs?: number;
}

export interface WsRolePushAuditOptions {
	mode?: Mode | string;
	root?: string;
	vault?: SessionVault;
	recorder?: TrafficRecorder;
	extraSecrets?: string[];
	timeoutMs?: number;
	wsFactory?: (url: string, init?: unknown) => WebSocket;
}

const WS_DEFAULT_MAX_FRAMES = 500;
const WS_DEFAULT_TIMEOUT_MS = 8_000;
const WS_DEFAULT_SETTLE_MS = 350;
const WS_ACK_KEYS = new Set([
	"ok", "ack", "type", "status", "success", "error", "message", "code", "pong", "ping", "event", "op",
]);
const WS_SENSITIVE_FIELD_RE =
	/["']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|passwd|api[_-]?key|authorization|bearer)["']?\s*[:=]\s*["']?([^"',}\s]{4,})/gi;

function wsSafeJsonParse(text: string): unknown {
	const trimmed = text.trim();
	if (!trimmed) return undefined;
	try {
		const value = JSON.parse(trimmed) as unknown;
		if (value && typeof value === "object") return value;
	} catch {
		// 非 JSON 帧，保持原文
	}
	return undefined;
}

function wsDecodePayload(opcode: number, payloadData: string): string {
	if (opcode !== 2) return payloadData;
	try {
		return Buffer.from(payloadData, "base64").toString("utf8");
	} catch {
		return payloadData;
	}
}

function wsDataToText(data: unknown): string {
	if (typeof data === "string") return data;
	if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
	if (ArrayBuffer.isView(data)) {
		return Buffer.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)).toString("utf8");
	}
	return "[二进制数据]";
}

function wsIsLikelyAckOrErrorText(text: string): boolean {
	const trimmed = text.trim();
	if (!trimmed) return true;
	const parsed = wsSafeJsonParse(trimmed);
	if (parsed !== undefined) {
		if (Array.isArray(parsed)) return parsed.length === 0;
		if (parsed && typeof parsed === "object") {
			const keys = Object.keys(parsed as Record<string, unknown>);
			if (keys.length === 0) return true;
			return keys.every((key) => WS_ACK_KEYS.has(key.toLowerCase()));
		}
		return true;
	}
	if (trimmed.length > 120) return false;
	return /^(ok|ack|pong|ping|success|error|unauthorized|forbidden|subscribed|subscribe[_-]?ack)\b/i.test(trimmed);
}

function wsLooksLikeSensitiveLeak(raw: string): boolean {
	WS_SENSITIVE_FIELD_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = WS_SENSITIVE_FIELD_RE.exec(raw)) !== null) {
		const value = (match[1] ?? "").trim();
		if (!value) continue;
		if (value === REDACTED_MARKER || value.includes(REDACTED_MARKER)) continue;
		if (/^\[?redacted\]?$/i.test(value)) continue;
		return true;
	}
	return false;
}

function wsIsAnonRole(role: string): boolean {
	const normalized = role.trim().toLowerCase();
	return normalized === "anon" || normalized === "anonymous";
}

function wsProtocolAllowed(rawUrl: string): boolean {
	try {
		const parsed = new URL(rawUrl);
		return parsed.protocol === "ws:" || parsed.protocol === "wss:";
	} catch {
		return false;
	}
}

export function attachCdpWebSocketAuditor(
	session: CdpSession,
	scope: ScopePolicy,
	opts?: {
		root?: string;
		vault?: SessionVault;
		recorder?: TrafficRecorder;
		extraSecrets?: string[];
		maxFrames?: number;
	},
): { getFrames(): CdpWebSocketFrameEvent[]; getBlockedUrls(): string[]; detach(): void } {
	const maxFrames = Math.max(1, opts?.maxFrames ?? WS_DEFAULT_MAX_FRAMES);
	const frames: CdpWebSocketFrameEvent[] = [];
	const blockedUrls: string[] = [];
	const urlByRequest = new Map<string, { rawUrl: string; blocked: boolean }>();
	const unsubscribers: Array<() => void> = [];
	let detached = false;

	const redactUrl = (rawUrl: string): string => {
		try {
			return redactTrafficUrl(rawUrl, { root: opts?.root, vault: opts?.vault, extraSecrets: opts?.extraSecrets });
		} catch {
			return "[无法脱敏的 WebSocket URL]";
		}
	};

	const redactText = (text: string): string =>
		scrubProtocolText(text, opts?.extraSecrets, opts?.root ?? opts?.vault);

	const pushFrame = (frame: CdpWebSocketFrameEvent): void => {
		if (detached) return;
		frames.push(frame);
		if (frames.length > maxFrames) frames.splice(0, frames.length - maxFrames);
	};

	const onCreated = (params: Record<string, unknown>): void => {
		const requestId = typeof params.requestId === "string" ? params.requestId : "";
		const rawUrl = typeof params.url === "string" ? params.url : "";
		if (!requestId || !rawUrl) return;
		const protocolOk = wsProtocolAllowed(rawUrl);
		const check = protocolOk
			? checkProtocolTargetScope(rawUrl, "GET", scope, undefined, "websocket")
			: ({ ok: false, reason: "仅允许 ws:// 或 wss:// WebSocket 连接" } as const);
		if (!check.ok) {
			const safeUrl = redactUrl(rawUrl);
			if (!blockedUrls.includes(safeUrl)) blockedUrls.push(safeUrl);
			urlByRequest.set(requestId, { rawUrl, blocked: true });
			return;
		}
		urlByRequest.set(requestId, { rawUrl, blocked: false });
	};

	const onFrame = (direction: "sent" | "received") => (params: Record<string, unknown>): void => {
		if (detached) return;
		const requestId = typeof params.requestId === "string" ? params.requestId : "";
		const entry = requestId ? urlByRequest.get(requestId) : undefined;
		const rawUrl = entry?.rawUrl ?? "";
		const response = params.response as Record<string, unknown> | undefined;
		const opcode = typeof response?.opcode === "number" ? response.opcode : 1;
		const payloadData = typeof response?.payloadData === "string" ? response.payloadData : "";
		const rawText = wsDecodePayload(opcode, payloadData);
		const scrubbed = redactText(rawText);
		pushFrame({
			requestId,
			url: rawUrl ? redactUrl(rawUrl) : "",
			direction,
			opcode,
			payloadData: scrubbed,
			timestamp: typeof params.timestamp === "number" ? params.timestamp : Date.now(),
			parsedJson: wsSafeJsonParse(scrubbed),
		});
	};

	const onClosed = (params: Record<string, unknown>): void => {
		const requestId = typeof params.requestId === "string" ? params.requestId : "";
		if (requestId) urlByRequest.delete(requestId);
	};

	unsubscribers.push(session.client.on("Network.webSocketCreated", onCreated));
	unsubscribers.push(session.client.on("Network.webSocketFrameSent", onFrame("sent")));
	unsubscribers.push(session.client.on("Network.webSocketFrameReceived", onFrame("received")));
	unsubscribers.push(session.client.on("Network.webSocketClosed", onClosed));

	return {
		getFrames: () => frames.map((frame) => ({ ...frame })),
		getBlockedUrls: () => [...blockedUrls],
		detach: () => {
			if (detached) return;
			detached = true;
			for (const unsubscribe of unsubscribers) {
				try {
					unsubscribe();
				} catch {
					// 忽略退订异常，确保其余监听器继续清理
				}
			}
			unsubscribers.length = 0;
			urlByRequest.clear();
		},
	};
}

export async function auditWebSocketCrossTenantPush(
	specs: readonly WsActiveAuditSpec[],
	scope: ScopePolicy,
	opts?: WsRolePushAuditOptions,
): Promise<{
	ok: boolean;
	blockedByScope: boolean;
	blockReason?: string;
	frames: CdpWebSocketFrameEvent[];
	findings: WebSocketAuditFinding[];
	fact: AutoFact | null;
}> {
	const frames: CdpWebSocketFrameEvent[] = [];
	const findings: WebSocketAuditFinding[] = [];
	const blockedReasons: string[] = [];
	const allowedSpecs: WsActiveAuditSpec[] = [];
	let vaultRef = opts?.vault;

	const redactWsUrl = (rawUrl: string): string => {
		try {
			return redactTrafficUrl(rawUrl, { root: opts?.root, vault: vaultRef, extraSecrets: opts?.extraSecrets });
		} catch {
			return "[无法脱敏的 WebSocket URL]";
		}
	};

	for (const spec of specs) {
		if (!wsProtocolAllowed(spec.wsUrl)) {
			blockedReasons.push(`已拒绝非 ws:// 或 wss:// 目标：${redactWsUrl(spec.wsUrl)}`);
			continue;
		}
		const check = checkProtocolTargetScope(spec.wsUrl, "GET", scope, opts?.mode, `websocket:${spec.role}`);
		if (!check.ok) {
			blockedReasons.push(check.reason);
			continue;
		}
		allowedSpecs.push(spec);
	}

	if (allowedSpecs.length === 0) {
		return {
			ok: false,
			blockedByScope: true,
			blockReason: blockedReasons.join("；") || "没有可用的 WebSocket 审计目标",
			frames,
			findings,
			fact: null,
		};
	}

	if (!vaultRef && opts?.root) {
		try {
			vaultRef = loadSessionVault(opts.root);
		} catch {
			// 会话库不可用时仅使用显式 headers
		}
	}

	const baseSecrets = [...(opts?.extraSecrets ?? [])];
	const findingKeys = new Set<string>();
	const addFinding = (finding: WebSocketAuditFinding): void => {
		const key = `${finding.kind}|${finding.url}|${finding.role}`;
		if (findingKeys.has(key)) return;
		findingKeys.add(key);
		findings.push(finding);
	};

	for (const spec of allowedSpecs) {
		const role = spec.role || "anon";
		const safeUrl = redactWsUrl(spec.wsUrl);
		let roleHeaders: Record<string, string> = {};
		if (vaultRef) {
			const fromVault = getRoleHeadersMap(vaultRef, role);
			if (fromVault) roleHeaders = { ...fromVault };
		}
		const mergedHeaders: Record<string, string> = { ...roleHeaders, ...(spec.headers ?? {}) };
		const extraSecrets = [...baseSecrets, ...collectSecretsFromHeaders(mergedHeaders)];
		const redactedHeaders = redactTrafficHeaders(mergedHeaders, {
			root: opts?.root,
			vault: vaultRef,
			extraSecrets,
		});
		const specFrames: CdpWebSocketFrameEvent[] = [];
		const specFindingKeys = new Set<string>();
		const addSpecFinding = (
			kind: WebSocketAuditFinding["kind"],
			severity: WebSocketAuditFinding["severity"],
			summary: string,
			sampleFrame: string,
		): void => {
			if (specFindingKeys.has(kind)) return;
			specFindingKeys.add(kind);
			addFinding({ kind, severity, url: safeUrl, role, summary, sampleFrame });
		};

		const timeoutMs = Math.max(1_000, spec.timeoutMs ?? opts?.timeoutMs ?? WS_DEFAULT_TIMEOUT_MS);
		const settleMs = Math.max(50, spec.settleMs ?? WS_DEFAULT_SETTLE_MS);

		let socket: WebSocket | null = null;
		try {
			if (opts?.wsFactory) {
				socket = opts.wsFactory(
					spec.wsUrl,
					Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : undefined,
				);
			} else {
				const Ctor = WebSocket as unknown as new (url: string, init?: unknown) => WebSocket;
				try {
					socket = new Ctor(
						spec.wsUrl,
						Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : undefined,
					);
				} catch {
					socket = new Ctor(spec.wsUrl);
				}
			}
		} catch {
			specFrames.length = 0;
			continue;
		}

		const ws = socket;
		if (!ws) continue;

		await new Promise<void>((resolve) => {
			let settled = false;
			let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
			let settleTimer: ReturnType<typeof setTimeout> | undefined;

			const finish = (): void => {
				if (settled) return;
				settled = true;
				if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
				if (settleTimer !== undefined) clearTimeout(settleTimer);
				try {
					ws.close();
				} catch {
					// 忽略关闭异常，仍继续清理句柄
				}
				ws.onopen = null;
				ws.onmessage = null;
				ws.onerror = null;
				ws.onclose = null;
				resolve();
			};

			timeoutTimer = setTimeout(finish, timeoutMs);

			ws.onopen = () => {
				if (settled) return;
				for (let index = 0; index < spec.subscribeMessages.length; index += 1) {
					const message = spec.subscribeMessages[index];
					const text = typeof message === "string" ? message : JSON.stringify(message);
					try {
						ws.send(text);
					} catch {
						break;
					}
					const scrubbedSent = scrubProtocolText(text, extraSecrets, opts?.root ?? vaultRef);
					specFrames.push({
						requestId: `local:${role}:${Date.now()}:${index}`,
						url: safeUrl,
						direction: "sent",
						opcode: 1,
						payloadData: scrubbedSent,
						timestamp: Date.now(),
						parsedJson: wsSafeJsonParse(scrubbedSent),
					});
				}
				settleTimer = setTimeout(finish, settleMs);
			};

			ws.onmessage = (event: { data: unknown }) => {
				if (settled) return;
				const rawText = wsDataToText(event.data);
				const scrubbed = scrubProtocolText(rawText, extraSecrets, opts?.root ?? vaultRef);
				const parsed = wsSafeJsonParse(scrubbed);
				specFrames.push({
					requestId: `local:${role}:${Date.now()}`,
					url: safeUrl,
					direction: "received",
					opcode: typeof event.data === "string" ? 1 : 2,
					payloadData: scrubbed,
					timestamp: Date.now(),
					parsedJson: parsed,
				});

				const sampleFrame = clipSafeSnippet(scrubbed, {
					root: opts?.root,
					vault: vaultRef,
					extraSecrets,
					maxChars: 300,
				});

				if (wsIsAnonRole(role) && !wsIsLikelyAckOrErrorText(scrubbed)) {
					addSpecFinding(
						"unauth_ws_subscription",
						"high",
						`匿名角色 ${role} 订阅后收到实质业务推送`,
						sampleFrame,
					);
				}

				const foreignMarkers = spec.foreignTenantMarkers ?? [];
				const hitMarkers = foreignMarkers.filter((marker) => marker && rawText.includes(marker));
				if (hitMarkers.length > 0) {
					const safeMarkers = hitMarkers
						.map((marker) => scrubProtocolText(marker, extraSecrets, opts?.root ?? vaultRef))
						.join("，");
					addSpecFinding(
						"cross_tenant_push",
						"high",
						`角色 ${role} 收到跨租户推送，命中标识：${safeMarkers}`,
						sampleFrame,
					);
				}

				if (wsLooksLikeSensitiveLeak(rawText)) {
					addSpecFinding(
						"sensitive_frame_leak",
						"high",
						`角色 ${role} 接收帧疑似暴露 token/secret/password 等凭据字段`,
						sampleFrame,
					);
				}
			};

			ws.onerror = () => {
				finish();
			};
			ws.onclose = () => {
				finish();
			};
		});

		frames.push(...specFrames);
		if (frames.length > 4_000) frames.splice(0, frames.length - 4_000);

		if (opts?.recorder) {
			const requestBody = clipSafeSnippet(
				spec.subscribeMessages
					.map((message) => (typeof message === "string" ? message : JSON.stringify(message)))
					.join("\n"),
				{ root: opts.root, vault: vaultRef, extraSecrets, maxChars: 800 },
			);
			const responseBody = clipSafeSnippet(
				specFrames.map((frame) => `[${frame.direction}] ${frame.payloadData}`).join("\n"),
				{ root: opts.root, vault: vaultRef, extraSecrets, maxChars: 2_000 },
			);
			recordProtocolTraffic(opts.recorder, {
				method: "WS",
				url: safeUrl,
				requestHeaders: redactedHeaders,
				requestBody,
				status: 101,
				responseBody,
				tags: ["ws", "ws-audit", role],
				role,
				note: specFindingKeys.size > 0 ? `检出 ${specFindingKeys.size} 个 WebSocket 风险` : "WebSocket 审计完成",
			});
		}
	}

	let fact: AutoFact | null = null;
	if (findings.length > 0) {
		const detail = scrubProtocolText(
			findings
				.map((finding) => `[${finding.severity}] ${finding.kind} @ ${finding.url} (${finding.role})：${finding.summary}`)
				.join("\n"),
			baseSecrets,
			opts?.root ?? vaultRef,
		);
		const output = clipSafeSnippet(
			findings.map((finding) => finding.sampleFrame).join("\n---\n"),
			{ root: opts?.root, vault: vaultRef, extraSecrets: baseSecrets, maxChars: 2_000 },
		);
		fact = {
			kind: "vuln",
			title: "WebSocket 跨租户/未授权推送风险",
			detail,
			command: `ws-audit ${allowedSpecs.map((spec) => redactWsUrl(spec.wsUrl)).join(" ")}`,
			output: scrubProtocolText(output, baseSecrets, opts?.root ?? vaultRef),
			meta: {
				paths: allowedSpecs.map((spec) => redactWsUrl(spec.wsUrl)),
				status: 101,
			},
		};
	}

	return {
		ok: true,
		blockedByScope: false,
		frames,
		findings,
		fact,
	};
}
// ===== Part 3: Next.js RSC Flight 与 gRPC-Web 协议引擎 =====

export interface RscFlightChunk {
	id: string;
	tag: string;
	rawPayload: string;
	parsedJson?: unknown;
	isErrorDigest: boolean;
}

export interface RscActionProbeSpec {
	name: string;
	url: string;
	actionId: string;
	args: unknown[];
	expectedAdminOnly?: boolean;
	headers?: Record<string, string>;
}

function sanitizeHeaderName(name: string): string {
	return name.replace(/[^\x21-\x7e]/g, "").replace(/[:]/g, "").trim();
}

function sanitizeHeaderValue(value: string): string {
	return value.replace(/[\r\n]+/g, " ").trim();
}

function mergeProtocolHeaders(
	...sources: Array<Record<string, string> | undefined>
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const src of sources) {
		if (!src) continue;
		for (const [rawKey, rawValue] of Object.entries(src)) {
			const key = sanitizeHeaderName(rawKey);
			if (!key) continue;
			out[key] = sanitizeHeaderValue(String(rawValue));
		}
	}
	return out;
}

function isSuccessHttp(status: number): boolean {
	return status >= 200 && status < 300;
}

export function parseRscFlightStream(body: string): RscFlightChunk[] {
	const chunks: RscFlightChunk[] = [];
	const normalized = body.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
	for (const rawLine of normalized.split("\n")) {
		const line = rawLine.trim();
		if (!line) continue;
		const colon = line.indexOf(":");
		if (colon < 0) continue;
		const id = line.slice(0, colon).trim();
		if (!id) continue;
		const rest = line.slice(colon + 1);
		const match = /^([A-Z]*)([\s\S]*)$/.exec(rest);
		const tag = match ? match[1] : "";
		const rawPayload = match ? match[2] : rest;
		let parsedJson: unknown;
		try {
			parsedJson = JSON.parse(rawPayload);
		} catch {
			parsedJson = undefined;
		}
		let isErrorDigest = tag === "E";
		if (
			!isErrorDigest &&
			parsedJson &&
			typeof parsedJson === "object" &&
			!Array.isArray(parsedJson)
		) {
			const obj = parsedJson as Record<string, unknown>;
			if (
				"digest" in obj ||
				"error" in obj ||
				(typeof obj.message === "string" && /error/i.test(obj.message))
			) {
				isErrorDigest = true;
			}
		}
		if (!isErrorDigest && /"digest"\s*:/.test(rawPayload)) {
			isErrorDigest = true;
		}
		chunks.push({ id, tag, rawPayload, parsedJson, isErrorDigest });
	}
	return chunks;
}

export function buildRscActionRequest(
	actionId: string,
	args: unknown[],
	extraHeaders?: Record<string, string>,
): { headers: Record<string, string>; body: string } {
	const cleanActionId = sanitizeHeaderValue(actionId).replace(/\s+/g, "");
	if (!cleanActionId) throw new Error("RSC actionId 不能为空");
	return {
		headers: mergeProtocolHeaders(extraHeaders, {
			Accept: "text/x-component",
			"Content-Type": "text/plain;charset=UTF-8",
			"Next-Action": cleanActionId,
		}),
		body: JSON.stringify(Array.isArray(args) ? args : []),
	};
}

function resolveProtocolRolePlan(
	bundle: ReturnType<typeof resolveRoleHeadersBundle>,
	adminRoles: readonly string[],
): { baselineRole: string; probeRoles: string[] } {
	const ordered = bundle.roleOrder.length > 0 ? bundle.roleOrder : ["anon"];
	const baselineRole =
		ordered.find((role) => isAdminLikeRole(role, adminRoles)) ??
		ordered[0] ??
		"anon";
	const probeRoles = [
		baselineRole,
		...ordered.filter((role) => role !== baselineRole),
	];
	if (!probeRoles.includes("anon")) probeRoles.push("anon");
	return { baselineRole, probeRoles };
}

function collectProtocolExtraSecrets(
	bundle: ReturnType<typeof resolveRoleHeadersBundle>,
	extra: readonly string[] = [],
): string[] {
	const out = [...extra, ...bundle.extraSecrets];
	for (const headers of bundle.roleHeaders.values()) {
		out.push(...collectSecretsFromHeaders(headers));
	}
	return [...new Set(out)];
}

function makeProtocolVulnFact(
	findings: ReadonlyArray<{
		kind: AuthDiffAnomalyKind;
		name: string;
		url: string;
		testedRole: string;
		baselineRole: string;
	}>,
	extraSecrets: readonly string[],
	rootOrVault: string | SessionVault,
	prefix: string,
): AutoFact | null {
	if (findings.length === 0) return null;
	const paths = [...new Set(findings.map((f) => f.url))];
	const detail = findings
		.map(
			(f) =>
				`- [${f.kind}] ${f.name} 角色 ${f.testedRole} / 基线 ${f.baselineRole} @ ${f.url}`,
		)
		.join("\n");
	return {
		kind: "vuln",
		title: `${prefix}越权（${findings.length} 项）`,
		detail: scrubProtocolText(detail, extraSecrets, rootOrVault),
		command: paths.map((url) => `POST ${url}`).join("\n"),
		output: scrubProtocolText(
			findings.map((f) => f.kind).join(", "),
			extraSecrets,
			rootOrVault,
		),
		meta: { paths },
	};
}

export async function diffRscActionRoles(
	specs: readonly RscActionProbeSpec[],
	rootOrVault: string | SessionVault,
	scope: ScopePolicy,
	opts?: {
		roles?: string[];
		extraRoleHeaders?: Record<string, Record<string, string>>;
		adminRoles?: string[];
		timeoutMs?: number;
		fetchFn?: typeof fetch;
		mode?: Mode | string;
		recorder?: TrafficRecorder;
		extraSecrets?: string[];
	},
): Promise<{
	ok: boolean;
	blockedByScope: boolean;
	blockReason?: string;
	findings: Array<{
		name: string;
		actionId: string;
		url: string;
		kind: AuthDiffAnomalyKind;
		severity: "high" | "medium";
		summary: string;
		baselineRole: string;
		testedRole: string;
		probes: Array<{
			role: string;
			status: number;
			chunkCount: number;
			hasErrorDigest: boolean;
			bodyHash: string;
			sampleSnippet: string;
		}>;
	}>;
	fact: AutoFact | null;
}> {
	const findings: Array<{
		name: string;
		actionId: string;
		url: string;
		kind: AuthDiffAnomalyKind;
		severity: "high" | "medium";
		summary: string;
		baselineRole: string;
		testedRole: string;
		probes: Array<{
			role: string;
			status: number;
			chunkCount: number;
			hasErrorDigest: boolean;
			bodyHash: string;
			sampleSnippet: string;
		}>;
	}> = [];
	const bundle = resolveRoleHeadersBundle(rootOrVault, {
		roles: opts?.roles,
		extraRoleHeaders: opts?.extraRoleHeaders,
		adminRoles: opts?.adminRoles,
	});
	const adminRoles = opts?.adminRoles ?? [];
	const { baselineRole, probeRoles } = resolveProtocolRolePlan(bundle, adminRoles);
	const extraSecrets = collectProtocolExtraSecrets(bundle, opts?.extraSecrets);
	const fetchFn = opts?.fetchFn ?? fetch;
	const timeoutMs = opts?.timeoutMs ?? 15_000;

	for (const spec of specs) {
		const scopeCheck = checkProtocolTargetScope(
			spec.url,
			"POST",
			scope,
			opts?.mode,
			spec.name,
		);
		if (!scopeCheck.ok) {
			return {
				ok: false,
				blockedByScope: true,
				blockReason: scopeCheck.reason,
				findings: [],
				fact: null,
			};
		}
		const redactedUrl = redactTrafficUrl(spec.url, {
			root: bundle.rootDir,
			vault: bundle.vaultRef,
			extraSecrets,
		});
		const probes: Array<{
			role: string;
			status: number;
			chunkCount: number;
			hasErrorDigest: boolean;
			bodyHash: string;
			sampleSnippet: string;
		}> = [];

		for (const role of probeRoles) {
			const roleHeaders = role === "anon" ? {} : bundle.roleHeaders.get(role) ?? {};
			const probeSecrets = [
				...extraSecrets,
				...collectSecretsFromHeaders(roleHeaders),
				...collectSecretsFromHeaders(spec.headers ?? {}),
			];
			const built = buildRscActionRequest(spec.actionId, spec.args, spec.headers);
			const merged = mergeProtocolHeaders(roleHeaders, built.headers);
			const started = Date.now();
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), timeoutMs);
			let status = 0;
			let responseText = "";
			let responseHeadersOut: Record<string, string> = {};
			try {
				const res = await fetchFn(spec.url, {
					method: "POST",
					headers: merged,
					body: built.body,
					signal: controller.signal,
				});
				status = res.status;
				responseHeadersOut = headersToRecord(res.headers);
				responseText = await res.text();
			} catch {
				status = 0;
			} finally {
				clearTimeout(timer);
			}
			const durationMs = Date.now() - started;
			let chunks: RscFlightChunk[] = [];
			try {
				chunks = parseRscFlightStream(responseText);
			} catch {
				chunks = [];
			}
			const hasErrorDigest = chunks.some((chunk) => chunk.isErrorDigest);
			const bodyHash = computeBodyHash(responseText).bodyHash;
			const sampleSnippet = clipSafeSnippet(responseText, {
				root: bundle.rootDir,
				vault: bundle.vaultRef,
				extraSecrets: probeSecrets,
				maxChars: 240,
			});
			probes.push({
				role,
				status,
				chunkCount: chunks.length,
				hasErrorDigest,
				bodyHash,
				sampleSnippet,
			});
			recordProtocolTraffic(opts?.recorder, {
				method: "POST",
				url: spec.url,
				requestHeaders: redactTrafficHeaders(merged, {
					root: bundle.rootDir,
					vault: bundle.vaultRef,
					extraSecrets: probeSecrets,
				}),
				requestBody:
					redactTrafficBody(built.body, {
						root: bundle.rootDir,
						vault: bundle.vaultRef,
						extraSecrets: probeSecrets,
						maxChars: 2000,
					}) ?? "",
				status,
				responseHeaders: redactTrafficHeaders(responseHeadersOut, {
					root: bundle.rootDir,
					vault: bundle.vaultRef,
					extraSecrets: probeSecrets,
				}),
				responseBody:
					redactTrafficBody(responseText, {
						root: bundle.rootDir,
						vault: bundle.vaultRef,
						extraSecrets: probeSecrets,
						maxChars: 2000,
					}) ?? "",
				durationMs,
				tags: ["rsc", "auth-diff"],
				role,
				note: `RSC action ${spec.actionId}`,
			});
		}

		const baselineProbe = probes.find((probe) => probe.role === baselineRole);
		if (
			!baselineProbe ||
			!isSuccessHttp(baselineProbe.status) ||
			baselineProbe.hasErrorDigest ||
			baselineProbe.chunkCount === 0
		) {
			continue;
		}
		for (const probe of probes) {
			if (probe.role === baselineRole) continue;
			if (
				!isSuccessHttp(probe.status) ||
				probe.hasErrorDigest ||
				probe.chunkCount === 0
			) {
				continue;
			}
			let kind: AuthDiffAnomalyKind;
			if (probe.role === "anon") {
				kind = "unauth_access";
			} else if (
				spec.expectedAdminOnly ||
				(isAdminLikeRole(baselineRole, adminRoles) &&
					!isAdminLikeRole(probe.role, adminRoles))
			) {
				kind = "vertical_bfla";
			} else {
				kind = "horizontal_bola";
			}
			const severity: "high" | "medium" =
				kind === "horizontal_bola" ? "medium" : "high";
			const summary = `Next.js Server Action ${spec.actionId}（${spec.name}）在角色 ${probe.role} 下越权成功，基线角色 ${baselineRole}。`;
			findings.push({
				name: spec.name,
				actionId: spec.actionId,
				url: redactedUrl,
				kind,
				severity,
				summary,
				baselineRole,
				testedRole: probe.role,
				probes,
			});
		}
	}

	return {
		ok: true,
		blockedByScope: false,
		findings,
		fact: makeProtocolVulnFact(
			findings,
			extraSecrets,
			rootOrVault,
			"Next.js RSC Server Action ",
		),
	};
}

// ----- gRPC-Web 5 字节头 + Protobuf Wire -----

export type ProtobufWireType = 0 | 1 | 2 | 5;

export interface ProtobufField {
	fieldNumber: number;
	wireType: ProtobufWireType;
	value: bigint | number | Uint8Array | string;
	utf8Text?: string;
	nestedFields?: ProtobufField[];
}

export interface GrpcWebFrame {
	compressed: boolean;
	isTrailer: boolean;
	payload: Uint8Array;
	trailers?: Record<string, string>;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) total += part.length;
	const out = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
	if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
		throw new Error("uint32 值非法");
	}
	buf[offset] = (value >>> 24) & 0xff;
	buf[offset + 1] = (value >>> 16) & 0xff;
	buf[offset + 2] = (value >>> 8) & 0xff;
	buf[offset + 3] = value & 0xff;
}

function readUint32BE(buf: Uint8Array, offset: number): number {
	if (offset < 0 || offset + 4 > buf.length) {
		throw new Error("读取 uint32 越界");
	}
	return (
		((buf[offset] * 0x1000000 +
			(buf[offset + 1] << 16) +
			(buf[offset + 2] << 8) +
			buf[offset + 3]) >>>
			0) >>> 0
	);
}

function isLikelyPrintableUtf8(text: string): boolean {
	if (text.length === 0) return false;
	for (let i = 0; i < text.length; i++) {
		const code = text.charCodeAt(i);
		if (code === 0x09 || code === 0x0a || code === 0x0d) continue;
		if (code < 0x20 || code === 0x7f) return false;
	}
	return true;
}

function bytesToBase64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(text: string): Uint8Array {
	return new Uint8Array(Buffer.from(text, "base64"));
}

function summarizeProtobufFields(fields: readonly ProtobufField[]): string {
	return fields
		.slice(0, 24)
		.map((field) => {
			let valueText: string;
			if (field.utf8Text !== undefined) {
				valueText = field.utf8Text;
			} else if (field.wireType === 2) {
				valueText = `<${field.value instanceof Uint8Array ? field.value.length : 0} bytes>`;
			} else {
				valueText = String(field.value);
			}
			return `${field.fieldNumber}:${field.wireType}=${valueText}`;
		})
		.join(", ");
}

function grpcMandatoryHeaders(useBase64Text: boolean): Record<string, string> {
	const contentType = useBase64Text
		? "application/grpc-web-text"
		: "application/grpc-web+proto";
	return {
		Accept: contentType,
		"Content-Type": contentType,
		"x-grpc-web": "1",
	};
}

export function encodeVarint(value: number | bigint): Uint8Array {
	let current: bigint;
	if (typeof value === "bigint") {
		current = value;
	} else {
		if (!Number.isFinite(value) || !Number.isInteger(value)) {
			throw new Error("Varint 输入必须是非负整数");
		}
		if (!Number.isSafeInteger(value)) {
			throw new Error("Varint number 必须是安全整数，超长值请使用 bigint");
		}
		current = BigInt(value);
	}
	if (current < 0n) throw new Error("Varint 输入不能为负数");
	if (current > 0xffffffffffffffffn) {
		throw new Error("Varint 超出 uint64 范围");
	}
	const out: number[] = [];
	do {
		let byte = Number(current & 0x7fn);
		current >>= 7n;
		if (current > 0n) byte |= 0x80;
		out.push(byte);
		if (out.length > 10) throw new Error("Varint 超过 10 字节");
	} while (current > 0n);
	return new Uint8Array(out);
}

export function decodeVarint(
	buf: Uint8Array,
	offset = 0,
): { value: bigint; nextOffset: number } {
	if (!Number.isInteger(offset) || offset < 0 || offset > buf.length) {
		throw new Error("Varint 偏移非法");
	}
	let value = 0n;
	let pos = offset;
	for (let i = 0; i < 10; i++) {
		if (pos >= buf.length) throw new Error("Varint 数据越界");
		const byte = buf[pos++];
		if (i === 9 && (byte & 0xfe) !== 0) {
			throw new Error("Varint 超过 uint64 范围");
		}
		value |= BigInt(byte & 0x7f) << BigInt(7 * i);
		if ((byte & 0x80) === 0) return { value, nextOffset: pos };
	}
	throw new Error("Varint 超过 10 字节");
}

export function encodeProtobufFields(
	fields: ReadonlyArray<{
		fieldNumber: number;
		wireType: ProtobufWireType;
		value: number | bigint | string | Uint8Array;
	}>,
): Uint8Array {
	const parts: Uint8Array[] = [];
	for (const field of fields) {
		if (
			!Number.isInteger(field.fieldNumber) ||
			field.fieldNumber < 1 ||
			field.fieldNumber > 536870911
		) {
			throw new Error("非法 Protobuf 字段号");
		}
		if (
			field.wireType !== 0 &&
			field.wireType !== 1 &&
			field.wireType !== 2 &&
			field.wireType !== 5
		) {
			throw new Error("不支持的 Protobuf wire type");
		}
		parts.push(
			encodeVarint(
				(BigInt(field.fieldNumber) << 3n) | BigInt(field.wireType),
			),
		);
		if (field.wireType === 0) {
			if (typeof field.value !== "number" && typeof field.value !== "bigint") {
				throw new Error("WireType 0 仅支持 number 或 bigint");
			}
			parts.push(encodeVarint(field.value));
		} else if (field.wireType === 1) {
			if (typeof field.value !== "number" && typeof field.value !== "bigint") {
				throw new Error("WireType 1 仅支持 number 或 bigint");
			}
			let current =
				typeof field.value === "bigint"
					? field.value
					: BigInt(Math.trunc(field.value));
			current &= 0xffffffffffffffffn;
			const bytes = new Uint8Array(8);
			for (let i = 0; i < 8; i++) {
				bytes[i] = Number(current & 0xffn);
				current >>= 8n;
			}
			parts.push(bytes);
		} else if (field.wireType === 2) {
			let bytes: Uint8Array;
			if (typeof field.value === "string") {
				bytes = new TextEncoder().encode(field.value);
			} else if (field.value instanceof Uint8Array) {
				bytes = field.value;
			} else {
				throw new Error("WireType 2 仅支持 string 或 Uint8Array");
			}
			parts.push(encodeVarint(bytes.length));
			parts.push(bytes);
		} else {
			if (typeof field.value !== "number" && typeof field.value !== "bigint") {
				throw new Error("WireType 5 仅支持 number 或 bigint");
			}
			let current =
				typeof field.value === "bigint"
					? Number(field.value & 0xffffffffn)
					: field.value >>> 0;
			const bytes = new Uint8Array(4);
			bytes[0] = current & 0xff;
			bytes[1] = (current >>> 8) & 0xff;
			bytes[2] = (current >>> 16) & 0xff;
			bytes[3] = (current >>> 24) & 0xff;
			parts.push(bytes);
		}
	}
	return concatBytes(parts);
}

export function decodeProtobufFields(
	buf: Uint8Array,
	maxDepth = 8,
): ProtobufField[] {
	const fields: ProtobufField[] = [];
	let offset = 0;
	while (offset < buf.length) {
		const key = decodeVarint(buf, offset);
		offset = key.nextOffset;
		const wireTypeNumber = Number(key.value & 7n);
		const fieldNumber = Number(key.value >> 3n);
		if (fieldNumber < 1 || fieldNumber > 536870911) {
			throw new Error("非法 Protobuf 字段号");
		}
		if (
			wireTypeNumber !== 0 &&
			wireTypeNumber !== 1 &&
			wireTypeNumber !== 2 &&
			wireTypeNumber !== 5
		) {
			throw new Error("不支持的 Protobuf wire type");
		}
		const wireType = wireTypeNumber as ProtobufWireType;
		if (wireType === 0) {
			const decoded = decodeVarint(buf, offset);
			offset = decoded.nextOffset;
			fields.push({ fieldNumber, wireType, value: decoded.value });
		} else if (wireType === 1) {
			if (offset + 8 > buf.length) throw new Error("Protobuf 64-bit 字段越界");
			let value = 0n;
			for (let i = 0; i < 8; i++) {
				value |= BigInt(buf[offset + i]) << BigInt(8 * i);
			}
			offset += 8;
			fields.push({ fieldNumber, wireType, value });
		} else if (wireType === 2) {
			const length = decodeVarint(buf, offset);
			offset = length.nextOffset;
			const size = Number(length.value);
			if (
				!Number.isSafeInteger(size) ||
				size < 0 ||
				offset + size > buf.length
			) {
				throw new Error("Protobuf 长度字段越界");
			}
			const slice = buf.subarray(offset, offset + size);
			offset += size;
			const field: ProtobufField = { fieldNumber, wireType, value: slice };
			let utf8Text: string | undefined;
			try {
				const decoded = new TextDecoder("utf-8", { fatal: true }).decode(slice);
				if (isLikelyPrintableUtf8(decoded)) utf8Text = decoded;
			} catch {
				utf8Text = undefined;
			}
			if (utf8Text !== undefined) {
				field.utf8Text = utf8Text;
			} else if (maxDepth > 0 && slice.length > 0) {
				try {
					const nested = decodeProtobufFields(slice, maxDepth - 1);
					if (nested.length > 0) field.nestedFields = nested;
				} catch {
					field.nestedFields = undefined;
				}
			}
			fields.push(field);
		} else {
			if (offset + 4 > buf.length) throw new Error("Protobuf 32-bit 字段越界");
			const value =
				(buf[offset] |
					(buf[offset + 1] << 8) |
					(buf[offset + 2] << 16) |
					(buf[offset + 3] << 24)) >>>
				0;
			offset += 4;
			fields.push({ fieldNumber, wireType, value });
		}
	}
	return fields;
}

export function encodeGrpcWebFrame(
	payload: Uint8Array,
	opts?: { compressed?: boolean; isTrailer?: boolean; compress?: boolean },
): Uint8Array {
	let finalPayload = payload;
	let compressedFlag = opts?.compressed === true;
	if (opts?.compress === true) {
		finalPayload = new Uint8Array(gzipSync(payload));
		compressedFlag = true;
	}
	if (finalPayload.length > 0xffffffff) {
		throw new Error("gRPC-Web 帧过大");
	}
	const flags =
		(compressedFlag ? 0x01 : 0x00) | (opts?.isTrailer ? 0x80 : 0x00);
	const out = new Uint8Array(5 + finalPayload.length);
	out[0] = flags;
	writeUint32BE(out, 1, finalPayload.length);
	out.set(finalPayload, 5);
	return out;
}

export function decodeGrpcWebFrames(raw: Uint8Array): GrpcWebFrame[] {
	const frames: GrpcWebFrame[] = [];
	let offset = 0;
	while (offset < raw.length) {
		if (raw.length - offset < 5) {
			throw new Error("gRPC-Web 帧头不足 5 字节");
		}
		const flags = raw[offset];
		const length = readUint32BE(raw, offset + 1);
		const start = offset + 5;
		const end = start + length;
		if (end > raw.length) throw new Error("gRPC-Web 帧长度越界");
		let payload: Uint8Array = raw.subarray(start, end);
		const compressed = (flags & 0x01) !== 0;
		const isTrailer = (flags & 0x80) !== 0;
		if (compressed) {
			try {
				payload = new Uint8Array(gunzipSync(payload));
			} catch {
				// 解压失败时保留原始载荷，交由上层字段解析失败处理。
			}
		}
		const frame: GrpcWebFrame = { compressed, isTrailer, payload };
		if (isTrailer) {
			const text = new TextDecoder().decode(payload);
			const trailers: Record<string, string> = {};
			for (const line of text.split(/\r?\n/)) {
				const index = line.indexOf(":");
				if (index <= 0) continue;
				const key = line.slice(0, index).trim().toLowerCase();
				const value = line.slice(index + 1).trim();
				if (key) trailers[key] = value;
			}
			frame.trailers = trailers;
		}
		frames.push(frame);
		offset = end;
	}
	return frames;
}

export interface GrpcWebMethodSpec {
	name: string;
	url: string;
	requestFields: ReadonlyArray<{
		fieldNumber: number;
		wireType: ProtobufWireType;
		value: number | bigint | string | Uint8Array;
	}>;
	expectedAdminOnly?: boolean;
	useBase64Text?: boolean;
	headers?: Record<string, string>;
}

export async function diffGrpcWebMethodRoles(
	specs: readonly GrpcWebMethodSpec[],
	rootOrVault: string | SessionVault,
	scope: ScopePolicy,
	opts?: {
		roles?: string[];
		extraRoleHeaders?: Record<string, Record<string, string>>;
		adminRoles?: string[];
		timeoutMs?: number;
		fetchFn?: typeof fetch;
		mode?: Mode | string;
		recorder?: TrafficRecorder;
		extraSecrets?: string[];
	},
): Promise<{
	ok: boolean;
	blockedByScope: boolean;
	blockReason?: string;
	findings: Array<{
		name: string;
		url: string;
		kind: AuthDiffAnomalyKind;
		severity: "high" | "medium";
		summary: string;
		baselineRole: string;
		testedRole: string;
		probes: Array<{
			role: string;
			httpStatus: number;
			grpcStatus: string;
			fieldCount: number;
			bodyHash: string;
			sampleSnippet: string;
		}>;
	}>;
	fact: AutoFact | null;
}> {
	const findings: Array<{
		name: string;
		url: string;
		kind: AuthDiffAnomalyKind;
		severity: "high" | "medium";
		summary: string;
		baselineRole: string;
		testedRole: string;
		probes: Array<{
			role: string;
			httpStatus: number;
			grpcStatus: string;
			fieldCount: number;
			bodyHash: string;
			sampleSnippet: string;
		}>;
	}> = [];
	const bundle = resolveRoleHeadersBundle(rootOrVault, {
		roles: opts?.roles,
		extraRoleHeaders: opts?.extraRoleHeaders,
		adminRoles: opts?.adminRoles,
	});
	const adminRoles = opts?.adminRoles ?? [];
	const { baselineRole, probeRoles } = resolveProtocolRolePlan(bundle, adminRoles);
	const extraSecrets = collectProtocolExtraSecrets(bundle, opts?.extraSecrets);
	const fetchFn = opts?.fetchFn ?? fetch;
	const timeoutMs = opts?.timeoutMs ?? 15_000;

	for (const spec of specs) {
		const scopeCheck = checkProtocolTargetScope(
			spec.url,
			"POST",
			scope,
			opts?.mode,
			spec.name,
		);
		if (!scopeCheck.ok) {
			return {
				ok: false,
				blockedByScope: true,
				blockReason: scopeCheck.reason,
				findings: [],
				fact: null,
			};
		}
		const redactedUrl = redactTrafficUrl(spec.url, {
			root: bundle.rootDir,
			vault: bundle.vaultRef,
			extraSecrets,
		});
		const requestPayload = encodeProtobufFields(spec.requestFields);
		const framed = encodeGrpcWebFrame(requestPayload);
		const useBase64Text = spec.useBase64Text === true;
		const requestBody: string | Uint8Array = useBase64Text
			? bytesToBase64(framed)
			: framed;
		const requestBodyForTraffic =
			typeof requestBody === "string" ? requestBody : bytesToBase64(requestBody);
		const mandatoryHeaders = grpcMandatoryHeaders(useBase64Text);
		const probes: Array<{
			role: string;
			httpStatus: number;
			grpcStatus: string;
			fieldCount: number;
			bodyHash: string;
			sampleSnippet: string;
		}> = [];
		const successfulRoles = new Set<string>();

		for (const role of probeRoles) {
			const roleHeaders = role === "anon" ? {} : bundle.roleHeaders.get(role) ?? {};
			const probeSecrets = [
				...extraSecrets,
				...collectSecretsFromHeaders(roleHeaders),
				...collectSecretsFromHeaders(spec.headers ?? {}),
			];
			const merged = mergeProtocolHeaders(
				roleHeaders,
				spec.headers,
				mandatoryHeaders,
			);
			const started = Date.now();
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), timeoutMs);
			let httpStatus = 0;
			let responseHeadersOut: Record<string, string> = {};
			let raw: Uint8Array = new Uint8Array(0);
			let responseBodyForTraffic = "";
			try {
				const res = await fetchFn(spec.url, {
					method: "POST",
					headers: merged,
					body: (typeof requestBody === "string" ? requestBody : new Uint8Array(requestBody)) as unknown as BodyInit,
					signal: controller.signal,
				});
				httpStatus = res.status;
				responseHeadersOut = headersToRecord(res.headers);
				const responseContentType = res.headers.get("content-type") ?? "";
				if (useBase64Text || responseContentType.includes("grpc-web-text")) {
					const text = await res.text();
					responseBodyForTraffic = text;
					try {
						raw = base64ToBytes(text);
					} catch {
						raw = new Uint8Array(0);
					}
				} else {
					const arrayBuffer = await res.arrayBuffer();
					raw = new Uint8Array(arrayBuffer);
					responseBodyForTraffic = bytesToBase64(raw);
				}
			} catch {
				httpStatus = 0;
			} finally {
				clearTimeout(timer);
			}
			const durationMs = Date.now() - started;
			let frames: GrpcWebFrame[] = [];
			try {
				frames = decodeGrpcWebFrames(raw);
			} catch {
				frames = [];
			}
			let grpcStatus = responseHeadersOut["grpc-status"] ?? "0";
			for (const frame of frames) {
				if (frame.isTrailer && frame.trailers?.["grpc-status"] !== undefined) {
					grpcStatus = frame.trailers["grpc-status"];
				}
			}
			let fieldCount = 0;
			let firstFields: ProtobufField[] = [];
			const firstDataFrame = frames.find((frame) => !frame.isTrailer);
			if (firstDataFrame) {
				try {
					firstFields = decodeProtobufFields(firstDataFrame.payload);
					fieldCount = firstFields.length;
				} catch {
					firstFields = [];
					fieldCount = 0;
				}
			}
			const bodyHash = computeBodyHash(raw).bodyHash;
			const sampleSource =
				firstFields.length > 0
					? summarizeProtobufFields(firstFields)
					: bytesToBase64(raw).slice(0, 240);
			const sampleSnippet = clipSafeSnippet(sampleSource, {
				root: bundle.rootDir,
				vault: bundle.vaultRef,
				extraSecrets: probeSecrets,
				maxChars: 240,
			});
			probes.push({
				role,
				httpStatus,
				grpcStatus,
				fieldCount,
				bodyHash,
				sampleSnippet,
			});
			if (isSuccessHttp(httpStatus) && grpcStatus === "0" && frames.length > 0) {
				successfulRoles.add(role);
			}
			recordProtocolTraffic(opts?.recorder, {
				method: "POST",
				url: spec.url,
				requestHeaders: redactTrafficHeaders(merged, {
					root: bundle.rootDir,
					vault: bundle.vaultRef,
					extraSecrets: probeSecrets,
				}),
				requestBody:
					redactTrafficBody(requestBodyForTraffic, {
						root: bundle.rootDir,
						vault: bundle.vaultRef,
						extraSecrets: probeSecrets,
						maxChars: 2000,
					}) ?? "",
				status: httpStatus,
				responseHeaders: redactTrafficHeaders(responseHeadersOut, {
					root: bundle.rootDir,
					vault: bundle.vaultRef,
					extraSecrets: probeSecrets,
				}),
				responseBody:
					redactTrafficBody(responseBodyForTraffic, {
						root: bundle.rootDir,
						vault: bundle.vaultRef,
						extraSecrets: probeSecrets,
						maxChars: 2000,
					}) ?? "",
				durationMs,
				tags: ["grpc-web", "auth-diff"],
				role,
				note: `gRPC-Web ${spec.name}`,
			});
		}

		if (!successfulRoles.has(baselineRole)) continue;
		for (const probe of probes) {
			if (probe.role === baselineRole) continue;
			if (!successfulRoles.has(probe.role)) continue;
			let kind: AuthDiffAnomalyKind;
			if (probe.role === "anon") {
				kind = "unauth_access";
			} else if (
				spec.expectedAdminOnly ||
				(isAdminLikeRole(baselineRole, adminRoles) &&
					!isAdminLikeRole(probe.role, adminRoles))
			) {
				kind = "vertical_bfla";
			} else {
				kind = "horizontal_bola";
			}
			const severity: "high" | "medium" =
				kind === "horizontal_bola" ? "medium" : "high";
			const summary = `gRPC-Web 方法 ${spec.name} 在角色 ${probe.role} 下调用成功（grpc-status=0，基线 ${baselineRole}）。`;
			findings.push({
				name: spec.name,
				url: redactedUrl,
				kind,
				severity,
				summary,
				baselineRole,
				testedRole: probe.role,
				probes,
			});
		}
	}

	return {
		ok: true,
		blockedByScope: false,
		findings,
		fact: makeProtocolVulnFact(
			findings,
			extraSecrets,
			rootOrVault,
			"gRPC-Web ",
		),
	};
}
