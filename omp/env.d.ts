/**
 * 女娲 v4.0 离线环境与宿主扩展自包含类型声明。
 *
 * 目标：无需任何外置 `node_modules`、`@types/node` 或 `@types/bun`，
 * 即可离线完成 `omp/*.ts` 与 `kb/*.ts` 的严格类型检查与 `bun build` 静态构建。
 */

interface ImportMeta {
	dir: string;
	path: string;
	url: string;
	main: boolean;
}

declare namespace NodeJS {
	interface ErrnoException extends Error {
		errno?: number;
		code?: string;
		path?: string;
		syscall?: string;
	}
	interface ProcessEnv {
		[key: string]: string | undefined;
	}
	interface WriteStream {
		write(chunk: string | Uint8Array): boolean;
	}
}

interface Buffer extends Uint8Array {
	toString(encoding?: string, start?: number, end?: number): string;
}

declare var Buffer: {
	from(data: string | ArrayBuffer | ArrayLike<number>, encoding?: string): Buffer;
	alloc(size: number, fill?: number | string): Buffer;
	byteLength(string: string | Uint8Array, encoding?: string): number;
	isBuffer(obj: unknown): obj is Buffer;
	concat(list: readonly Uint8Array[], totalLength?: number): Buffer;
};

declare var process: {
	env: NodeJS.ProcessEnv;
	argv: string[];
	pid: number;
	platform: string;
	arch: string;
	cwd(): string;
	exit(code?: number): never;
	kill(pid: number, signal?: string | number): boolean;
	stdout: NodeJS.WriteStream;
	stderr: NodeJS.WriteStream;
};

declare namespace Bun {
	interface BunFile {
		text(): Promise<string>;
		json<T = unknown>(): Promise<T>;
		bytes(): Promise<Uint8Array>;
		exists(): Promise<boolean>;
		readonly size: number;
	}
	function file(path: string | URL): BunFile;
	function write(destination: string | URL | BunFile, input: string | Uint8Array | Blob): Promise<number>;
	function sleep(ms: number): Promise<void>;
	function which(bin: string, options?: { PATH?: string; cwd?: string }): string | null;
	function serve(options: Record<string, unknown>): {
		port: number;
		hostname: string;
		url: URL;
		stop(closeActiveConnections?: boolean): void;
	};
	function plugin(spec: {
		name: string;
		setup(build: {
			onLoad(
				opts: { filter: RegExp; namespace?: string },
				cb: (args: { path: string }) => Promise<{ contents: string; loader?: string }> | { contents: string; loader?: string },
			): void;
		}): void | Promise<void>;
	}): void;
	const version: string;
	const main: string;
}

declare module "bun:sqlite" {
	export interface Statement<TReturn = Record<string, unknown>, TParams extends unknown[] = unknown[]> {
		all(...params: TParams): TReturn[];
		get(...params: TParams): TReturn | null;
		run(...params: TParams): { changes: number; lastInsertRowid: number | bigint };
		values(...params: TParams): unknown[][];
		finalize(): void;
	}

	export class Database {
		readonly filename: string;
		constructor(filename?: string, options?: { readonly?: boolean; create?: boolean; readwrite?: boolean; strict?: boolean });
		exec(sql: string): this;
		run(sql: string, ...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
		query<TReturn = Record<string, unknown>, TParams extends unknown[] = unknown[]>(sql: string): Statement<TReturn, TParams>;
		prepare<TReturn = Record<string, unknown>, TParams extends unknown[] = unknown[]>(sql: string): Statement<TReturn, TParams>;
		transaction<TArgs extends unknown[], TReturn>(fn: (...args: TArgs) => TReturn): (...args: TArgs) => TReturn;
		close(throwOnError?: boolean): void;
	}
}

declare module "@oh-my-pi/pi-coding-agent" {
	export interface ZodTypeLike<T = any> {
		optional(): ZodTypeLike<T | undefined>;
		default(value: T): ZodTypeLike<T>;
		describe(description: string): ZodTypeLike<T>;
	}

	export interface ZodLike {
		string(): ZodTypeLike<string>;
		number(): ZodTypeLike<number>;
		boolean(): ZodTypeLike<boolean>;
		enum<const T extends readonly [string, ...string[]]>(values: T): ZodTypeLike<T[number]>;
		array<T>(schema: ZodTypeLike<T>): ZodTypeLike<T[]>;
		object<T extends Record<string, ZodTypeLike<any>>>(
			shape: T,
		): ZodTypeLike<{ [K in keyof T]: T[K] extends ZodTypeLike<infer U> ? U : any }>;
	}

	export interface ExtensionUiTheme {
		fg(color: string, text: string): string;
		bold(text: string): string;
	}

	export interface ExtensionUi {
		theme: ExtensionUiTheme;
		setStatus(key: string, text: string | undefined): void;
		setWidget(key: string, content: unknown, options?: Record<string, unknown>): void;
		setTitle?(title: string): void;
		notify(message: string, level?: "info" | "warning" | "error"): void;
		custom<T = unknown>(
			factory: (tui: unknown, theme: ExtensionUiTheme, kb: unknown, done: (val: T) => void) => unknown,
			options?: Record<string, unknown>,
		): Promise<T>;
	}

	export interface ExtensionContext {
		cwd: string;
		agent?: {
			kind?: "main" | "sub" | string;
			id?: string;
			name?: string;
			parentId?: string;
			depth?: number;
		};
		sessionManager: {
			getSessionId(): string;
			getParentSessionId?(): string | undefined;
		};
		ui: ExtensionUi;
		isIdle?(): boolean;
		hasPendingMessages?(): boolean;
		getContextUsage?(): { tokens?: number; usedTokens?: number } | undefined;
	}

	export interface ToolCallEvent {
		toolName: string;
		input?: Record<string, unknown>;
	}

	export interface SessionStopEvent {
		session_id?: string;
		stop_hook_active?: boolean;
	}

	export interface ToolDefinition<TParams = any> {
		name: string;
		label: string;
		description: string;
		loadMode?: "essential" | "deferred" | string;
		parameters: ZodTypeLike<TParams>;
		execute(
			id: string,
			params: TParams,
			signal: AbortSignal | undefined,
			onUpdate: unknown,
			ctx: ExtensionContext,
		): Promise<{ content: Array<{ type: "text"; text: string }>; details?: Record<string, unknown> }>;
	}

	export interface CommandDefinition {
		description: string;
		getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string }>;
		handler: (args: string, ctx: ExtensionContext) => Promise<void> | void;
	}

	export interface ExtensionAPI {
		zod: ZodLike;
		registerTool<TParams = any>(tool: ToolDefinition<TParams>): void;
		registerCommand?(name: string, command: CommandDefinition): void;
		sendUserMessage(text: string): void;
		sendMessage(
			message: { customType: string; content: string; display?: boolean },
			options?: { triggerTurn?: boolean; deliverAs?: string },
		): void;
		on(event: "session_start", handler: (event: unknown, ctx: ExtensionContext) => void): void;
		on(event: "session_shutdown", handler: (event: unknown, ctx: ExtensionContext) => void): void;
		on(event: "before_subagent_spawn", handler: (event: Record<string, unknown>, ctx: ExtensionContext) => unknown): void;
		on(event: "tool_execution_end", handler: (event: unknown, ctx: ExtensionContext) => void): void;
		on(event: "tool_call", handler: (event: ToolCallEvent, ctx: ExtensionContext) => { block: true; reason: string } | void): void;
		on(event: "session_stop", handler: (event: SessionStopEvent, ctx: ExtensionContext) => { decision: "block"; reason: string } | undefined | void): void;
		on(event: string, handler: (...args: any[]) => any): void;
	}
}

declare module "node:fs" {
	export interface Stats {
		size: number;
		mtimeMs: number;
		mode: number;
		isFile(): boolean;
		isDirectory(): boolean;
		isSymbolicLink(): boolean;
	}
	export function existsSync(path: string): boolean;
	export function readFileSync(path: string): Buffer;
	export function readFileSync(path: string, encoding: BufferEncoding | "utf8" | "utf-8"): string;
	export function writeFileSync(path: string, data: string | Uint8Array, options?: string | { encoding?: string; mode?: number }): void;
	export function appendFileSync(path: string, data: string | Uint8Array, options?: string | { encoding?: string; mode?: number }): void;
	export function mkdirSync(path: string, options?: { recursive?: boolean; mode?: number }): string | undefined;
	export function readdirSync(path: string, options?: { withFileTypes?: false }): string[];
	export function readdirSync(path: string, options: { withFileTypes: true }): Array<{ name: string; isFile(): boolean; isDirectory(): boolean }>;
	export function statSync(path: string): Stats;
	export function lstatSync(path: string): Stats;
	export function realpathSync(path: string): string;
	export function renameSync(oldPath: string, newPath: string): void;
	export function unlinkSync(path: string): void;
	export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
	export function chmodSync(path: string, mode: number): void;
	export function openSync(path: string, flags: string | number, mode?: number): number;
	export function writeSync(fd: number, buffer: string | Uint8Array): number;
	export function readSync(fd: number, buffer: Uint8Array, offset: number, length: number, position: number | null): number;
	export function fsyncSync(fd: number): void;
	export function closeSync(fd: number): void;
	export function mkdtempSync(prefix: string): string;
	export function copyFileSync(src: string, dest: string): void;
}

declare module "node:path" {
	export const sep: string;
	export const delimiter: string;
	export function join(...paths: string[]): string;
	export function resolve(...paths: string[]): string;
	export function dirname(path: string): string;
	export function basename(path: string, suffix?: string): string;
	export function extname(path: string): string;
	export function relative(from: string, to: string): string;
	export function isAbsolute(path: string): boolean;
}

declare module "node:os" {
	export function homedir(): string;
	export function tmpdir(): string;
	export function hostname(): string;
	export function platform(): string;
}

declare module "node:crypto" {
	export interface Hash {
		update(data: string | Uint8Array): this;
		digest(encoding: "hex" | "base64" | "base64url"): string;
		digest(): Buffer;
	}
	export function createHash(algorithm: string): Hash;
	export function randomUUID(): string;
}

declare module "node:zlib" {
	export function gzipSync(buf: string | Uint8Array): Buffer;
	export function gunzipSync(buf: Uint8Array): Buffer;
}

declare module "node:child_process" {
	export interface SpawnSyncReturns<T> {
		pid: number;
		output: Array<T | null>;
		stdout: T;
		stderr: T;
		status: number | null;
		signal: string | null;
		error?: Error;
	}
	export function spawnSync(
		command: string,
		args?: readonly string[],
		options?: {
			cwd?: string;
			env?: Record<string, string | undefined>;
			encoding?: "utf8" | "utf-8" | string;
			timeout?: number;
			maxBuffer?: number;
			input?: string | Uint8Array;
			stdio?: unknown;
		},
	): SpawnSyncReturns<string>;
}

declare module "node:timers" {
	export function setInterval(callback: (...args: any[]) => void, ms?: number): { unref(): void; ref(): void };
	export function clearInterval(handle: unknown): void;
}

type BufferEncoding = "ascii" | "utf8" | "utf-8" | "utf16le" | "ucs2" | "ucs-2" | "base64" | "base64url" | "latin1" | "binary" | "hex";
