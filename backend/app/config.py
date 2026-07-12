"""Application settings.

SentinelForge is provider-neutral: it talks to any OpenAI-compatible chat
completions endpoint (Groq, Together, Fireworks, a local vLLM/Ollama, or a
hosted API). The default configuration targets **Groq** running open-source
Llama models, which is what this project is tuned for.

The settings below expose clean, provider-neutral names (``llm_api_key``,
``llm_model_smart`` …). For backwards compatibility with the project's Qwen
origins, the legacy ``DASHSCOPE_API_KEY`` / ``QWEN_*`` environment variables are
still accepted as aliases, and ``settings.qwen_*`` properties still resolve, so
existing ``.env`` files and older imports keep working unchanged.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # ---- LLM provider (OpenAI-compatible: Groq, Together, vLLM, Ollama, …) ----
    # Two capability tiers keep OSS usage cheap and predictable:
    #   * smart — a 70B-class model for judgment + tool use (triage/investigate)
    #   * fast  — an 8B-class model for cheap classification + normalization
    llm_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("LLM_API_KEY", "GROQ_API_KEY", "DASHSCOPE_API_KEY"),
    )
    llm_base_url: str = Field(
        default="https://api.groq.com/openai/v1",
        validation_alias=AliasChoices("LLM_BASE_URL", "QWEN_BASE_URL"),
    )
    llm_provider: str = Field(
        default="groq",
        validation_alias=AliasChoices("LLM_PROVIDER"),
        description="Informational label: groq | together | vllm | ollama | dashscope | openai",
    )
    llm_model_smart: str = Field(
        default="llama-3.3-70b-versatile",
        validation_alias=AliasChoices("LLM_MODEL_SMART", "QWEN_MODEL_MAX", "QWEN_MODEL_PLUS"),
    )
    llm_model_fast: str = Field(
        default="llama-3.1-8b-instant",
        validation_alias=AliasChoices("LLM_MODEL_FAST", "QWEN_MODEL_FLASH"),
    )
    # Optional dedicated reasoning model (e.g. deepseek-r1-distill-llama-70b on
    # Groq). When empty, P1/P2 triage reasons in-line with the smart model.
    llm_model_reasoning: str = Field(
        default="",
        validation_alias=AliasChoices("LLM_MODEL_REASONING"),
    )
    llm_request_timeout_seconds: int = Field(
        default=60,
        validation_alias=AliasChoices("LLM_REQUEST_TIMEOUT_SECONDS", "QWEN_REQUEST_TIMEOUT_SECONDS"),
    )
    # Local sentence-transformers embedding model for runbook semantic search
    # (no API cost — runs on CPU). Falls back to keyword search if unavailable.
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2",
        validation_alias=AliasChoices("EMBEDDING_MODEL", "QWEN_EMBEDDING_MODEL"),
    )

    # ---- Database ----
    database_url: str = "postgresql://sentinelforge:sentinelforge@postgres:5432/sentinelforge"

    # ---- Redis ----
    redis_url: str = "redis://redis:6379/0"

    # ---- External tools (blank => realistic mock) ----
    elasticsearch_url: str = ""
    elasticsearch_api_key: str = ""
    prometheus_url: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    slack_bot_token: str = ""
    slack_channel_id: str = ""
    cloudflare_api_token: str = ""
    cloudflare_zone_id: str = ""
    use_mock_tools: bool = True

    # ---- Knowledge base / runbooks ----
    runbooks_dir: str = Field(default="", validation_alias=AliasChoices("RUNBOOKS_DIR"))
    chroma_dir: str = Field(default="", validation_alias=AliasChoices("CHROMA_DIR"))

    # ---- MCP ----
    runbook_mcp_sse_url: str = "http://mcp-server:8001/sse"
    jira_mcp_sse_url: str = "http://mcp-server:8001/sse"
    github_mcp_token: str = ""
    jira_mcp_token: str = ""

    # ---- Detection-as-code ----
    detections_dir: str = "detections/generated"

    # ---- Authentication / RBAC ----
    default_admin_password: str = "changeme-admin"
    auth_dev_bypass: bool = True

    # ---- Application ----
    secret_key: str = "dev-secret-change-me"
    environment: str = "development"
    log_level: str = "INFO"
    frontend_url: str = "http://localhost:3000"
    backend_url: str = "http://localhost:8000"

    # ---- Alert correlation / dedup engine ----
    # Alerts that share an entity (IP/user/host) or fingerprint with an OPEN
    # incident inside this window are folded into it instead of spawning a new
    # pipeline run — the core defence against alert-storm fatigue.
    correlation_enabled: bool = True
    correlation_window_seconds: int = 1800  # 30 minutes

    # ---- HITL auto-approval timeouts (minutes) ----
    auto_approve_timeout_p4: int = 5
    auto_approve_timeout_p3: int = 15
    auto_approve_timeout_p2: int = 2

    # ---- Action safety / guardrails (production containment) ----
    # The deterministic authorization layer between the LLM's proposed action and
    # any real mutation. The LLM never authorizes an action; this does.
    action_kill_switch: bool = False          # global emergency stop for all mutating actions
    action_dry_run_only: bool = True          # simulate mutations; never actually mutate prod (safe default)
    action_enabled_types: str = (             # only these action types may run at all
        "notification,block_ip,suspend_account,isolate_host,rotate_credentials,quarantine_file"
    )
    # Extra protected targets (added to the safe built-in defaults). Comma-separated.
    # Globs allowed for users/hosts (fnmatch). IPs/CIDRs for the block list.
    action_protected_ip_cidrs: str = ""       # never block these (RFC1918 + loopback always protected)
    action_protected_users: str = ""          # never suspend/rotate (break-glass/service accts always protected)
    action_protected_hosts: str = ""          # never isolate (domain controllers etc.)
    # Blast-radius / rate limits.
    action_max_per_incident: int = 10
    action_max_per_window: int = 25
    action_window_seconds: int = 300
    # Severities whose mutating actions need a second, distinct approver.
    action_two_person_severities: str = "P1_CRITICAL"

    # ---- Provider-neutral capability flags ----
    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)

    @property
    def is_dashscope(self) -> bool:
        """DashScope (Qwen Cloud) supports a few params Groq/OSS endpoints don't
        (parallel_tool_calls, strict json_schema, enable_thinking extra_body)."""
        return "dashscope" in self.llm_base_url.lower()

    # ---- Backwards-compatible aliases (legacy Qwen naming) ----
    @property
    def qwen_enabled(self) -> bool:
        return self.llm_enabled

    @property
    def has_openai_key(self) -> bool:
        return self.llm_enabled

    @property
    def dashscope_api_key(self) -> str:
        return self.llm_api_key

    @property
    def qwen_base_url(self) -> str:
        return self.llm_base_url

    @property
    def qwen_model_max(self) -> str:
        return self.llm_model_smart

    @property
    def qwen_model_plus(self) -> str:
        return self.llm_model_smart

    @property
    def qwen_model_flash(self) -> str:
        return self.llm_model_fast

    @property
    def qwen_embedding_model(self) -> str:
        return self.embedding_model

    @property
    def qwen_request_timeout_seconds(self) -> int:
        return self.llm_request_timeout_seconds


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
