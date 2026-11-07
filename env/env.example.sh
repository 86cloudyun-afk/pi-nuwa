#!/usr/bin/env bash
# 女娲运行环境模板：复制到 ${SAPPER_HOME:-$HOME/sapper-lab}/env.sh 后填入自己的 key。
# 这份文件只放网关与模型参数，不放任何真实凭据。

export SAPPER_HOME="${SAPPER_HOME:-$HOME/sapper-lab}"
export PATH="$HOME/.local/bin:$SAPPER_HOME/bin:$PATH"

# ---------- 主脑网关（Anthropic 兼容口） ----------
export GLM_BASE_URL="https://open.bigmodel.cn/api/anthropic"
export GLM_API_KEY="GLM_API_KEY_HERE"
export SAPPER_MODEL="glm-5.3-flash[1m]"
# omp 用 zai provider 调 GLM，认这两个变量名
export ZAI_API_KEY="$GLM_API_KEY"
export ZHIPU_API_KEY="$GLM_API_KEY"

# ---------- 量产模型（soldier/scout） ----------
export DEEPSEEK_BASE_URL="https://api.deepseek.com/anthropic"
export DEEPSEEK_API_KEY="DEEPSEEK_API_KEY_HERE"
export SAPPER_MODEL_DS="deepseek-flash"
export SAPPER_MODEL_FLASH="deepseek-flash"

# ---------- 默认网关 ----------
export ANTHROPIC_BASE_URL="$GLM_BASE_URL"
export ANTHROPIC_AUTH_TOKEN="$GLM_API_KEY"

# ---------- 额度熔断：主脑耗尽切备用军 ----------
export SAPPER_KEY_POOL='[{"base_url":"https://open.bigmodel.cn/api/anthropic","token":"GLM_API_KEY_HERE","model":"glm-5.3-flash[1m]"},{"base_url":"https://api.deepseek.com/anthropic","token":"DEEPSEEK_API_KEY_HERE","model":"deepseek-flash"}]'

export SAPPER_RETRY_MODEL=3
export SAPPER_TIMEOUT=900
export SAPPER_PARALLEL=3
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export DISABLE_AUTOUPDATER=1

sapper-glm() { export ANTHROPIC_BASE_URL="$GLM_BASE_URL" ANTHROPIC_AUTH_TOKEN="$GLM_API_KEY" SAPPER_MODEL="glm-5.3-flash[1m]"; echo "gateway=GLM model=$SAPPER_MODEL"; }
sapper-ds()  { export ANTHROPIC_BASE_URL="$DEEPSEEK_BASE_URL" ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" SAPPER_MODEL="$SAPPER_MODEL_DS"; echo "gateway=DeepSeek model=$SAPPER_MODEL"; }
sapper-who() { echo "gateway=$ANTHROPIC_BASE_URL model=$SAPPER_MODEL ds=$SAPPER_MODEL_DS"; }

# ---------- 引擎：sapper 通过 SAPPER_BIN 调 agent CLI ----------
export SAPPER_BIN="${SAPPER_BIN:-$SAPPER_HOME/bin/omp-claude}"
sapper-engine-omp()    { export SAPPER_BIN="$SAPPER_HOME/bin/omp-claude"; echo "engine=omp ($SAPPER_BIN)"; }
sapper-engine-claude() { export SAPPER_BIN="claude"; echo "engine=claude"; }
sapper-engine()        { echo "engine=$SAPPER_BIN"; }
