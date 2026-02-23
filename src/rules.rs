// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use colored::{ColoredString, Colorize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: &'static str,
    pub secret_group: usize,
    pub severity: Severity,
    pub tags: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity { Critical, High, Medium, Low, Warning }

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Warning  => write!(f, "WARNING"),
        }
    }
}

pub fn severity_color(s: &Severity) -> ColoredString {
    match s {
        Severity::Critical => s.to_string().red().bold(),
        Severity::High     => s.to_string().yellow().bold(),
        Severity::Medium   => s.to_string().cyan(),
        Severity::Low      => s.to_string().white(),
        Severity::Warning  => s.to_string().bright_yellow(),
    }
}

pub fn builtin_rules() -> Vec<Rule> { vec![
    // ── Cloud / VCS ──────────────────────────────────────────────────────────
    Rule { id: "aws-access-key",          description: "AWS Access Key ID",                  pattern: r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", secret_group: 0, severity: Severity::Critical, tags: vec!["aws","cloud"] },
    Rule { id: "aws-secret-key",          description: "AWS Secret Access Key",              pattern: r#"(?i)aws[_\-\s\.]{0,5}secret[_\-\s\.]{0,5}(access[_\-\s\.]{0,5})?key["'\s]*[:=]["'\s]*([A-Za-z0-9+/]{40})"#, secret_group: 2, severity: Severity::Critical, tags: vec!["aws","cloud"] },
    Rule { id: "github-pat",              description: "GitHub Personal Access Token",       pattern: r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}", secret_group: 0, severity: Severity::Critical, tags: vec!["github","token"] },
    Rule { id: "github-fine-grained-pat", description: "GitHub Fine-Grained PAT",           pattern: r"github_pat_[A-Za-z0-9_]{82}", secret_group: 0, severity: Severity::Critical, tags: vec!["github","token"] },
    Rule { id: "gitlab-pat",              description: "GitLab Personal Access Token",       pattern: r"glpat-[A-Za-z0-9\-]{20}", secret_group: 0, severity: Severity::Critical, tags: vec!["gitlab","token"] },
    Rule { id: "google-api-key",          description: "Google API Key",                    pattern: r"AIza[0-9A-Za-z\-_]{35}", secret_group: 0, severity: Severity::High, tags: vec!["google","cloud"] },
    Rule { id: "google-oauth-client",     description: "Google OAuth Client Secret",        pattern: r"GOCSPX-[A-Za-z0-9\-_]{28}", secret_group: 0, severity: Severity::High, tags: vec!["google","oauth"] },
    Rule { id: "stripe-secret",           description: "Stripe Secret Key",                 pattern: r"sk_(live|test)_[A-Za-z0-9]{24,}", secret_group: 0, severity: Severity::Critical, tags: vec!["stripe","payment"] },
    Rule { id: "stripe-publishable",      description: "Stripe Publishable Key",            pattern: r"pk_(live|test)_[A-Za-z0-9]{24,}", secret_group: 0, severity: Severity::Low, tags: vec!["stripe","payment"] },
    Rule { id: "slack-token",             description: "Slack Bot/User Token",              pattern: r"xox[baprs]-([0-9a-zA-Z]{10,48})", secret_group: 0, severity: Severity::High, tags: vec!["slack"] },
    Rule { id: "slack-webhook",           description: "Slack Webhook URL",                 pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", secret_group: 0, severity: Severity::High, tags: vec!["slack","webhook"] },
    Rule { id: "sendgrid-api",            description: "SendGrid API Key",                  pattern: r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", secret_group: 0, severity: Severity::High, tags: vec!["sendgrid","email"] },
    Rule { id: "twilio-account-sid",      description: "Twilio Account SID",               pattern: r"AC[a-z0-9]{32}", secret_group: 0, severity: Severity::High, tags: vec!["twilio"] },
    Rule { id: "jwt-token",               description: "JSON Web Token",                    pattern: r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", secret_group: 0, severity: Severity::Medium, tags: vec!["jwt","auth"] },
    Rule { id: "private-key-header",      description: "Private Key (PEM)",                 pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY( BLOCK)?-----", secret_group: 0, severity: Severity::Critical, tags: vec!["crypto","key"] },
    Rule { id: "generic-secret",          description: "Generic high-entropy secret",       pattern: r#"(?i)(secret|password|passwd|pwd|api[_-]?key|auth[_-]?token|access[_-]?token)["'\s]*[:=]["'\s]+([A-Za-z0-9!@#$%^&*()_+\-=]{16,})"#, secret_group: 2, severity: Severity::Medium, tags: vec!["generic"] },
    Rule { id: "basic-auth-url",          description: "Credentials in URL",                pattern: r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^:@\s]+@[^@\s]+", secret_group: 0, severity: Severity::High, tags: vec!["url","credentials"] },
    Rule { id: "npm-token",               description: "NPM Access Token",                  pattern: r"npm_[A-Za-z0-9]{36}", secret_group: 0, severity: Severity::High, tags: vec!["npm"] },
    Rule { id: "docker-hub-pat",          description: "Docker Hub PAT",                   pattern: r"dckr_pat_[A-Za-z0-9\-_]{27}", secret_group: 0, severity: Severity::High, tags: vec!["docker"] },

    // ── LLM / AI ─────────────────────────────────────────────────────────────
    Rule { id: "openai-api-key",          description: "OpenAI API Key",                    pattern: r"sk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{32,}T3BlbkFJ[A-Za-z0-9\-_]{20,}", secret_group: 0, severity: Severity::Critical, tags: vec!["llm","openai","ai"] },
    Rule { id: "openai-api-key-new",      description: "OpenAI API Key (sk-proj format)",  pattern: r"sk-proj-[A-Za-z0-9\-_]{50,}", secret_group: 0, severity: Severity::Critical, tags: vec!["llm","openai","ai"] },
    Rule { id: "anthropic-api-key",       description: "Anthropic / Claude API Key",        pattern: r"sk-ant-(?:api03-)?[A-Za-z0-9\-_]{32,}", secret_group: 0, severity: Severity::Critical, tags: vec!["llm","anthropic","ai"] },
    Rule { id: "cohere-api-key",          description: "Cohere API Key",                    pattern: r"(?i)(?:cohere[._-]?(?:api[._-]?)?key|CO_API_KEY)\s*[=:]\s*([A-Za-z0-9]{40})", secret_group: 1, severity: Severity::Critical, tags: vec!["llm","cohere","ai"] },
    Rule { id: "mistral-api-key",         description: "Mistral AI API Key",                pattern: r"(?i)(?:mistral[._-]?(?:api[._-]?)?key|MISTRAL_API_KEY)\s*[=:]\s*([A-Za-z0-9]{32})", secret_group: 1, severity: Severity::Critical, tags: vec!["llm","mistral","ai"] },
    Rule { id: "huggingface-token",       description: "Hugging Face API Token",            pattern: r"hf_[A-Za-z0-9]{32,}", secret_group: 0, severity: Severity::High, tags: vec!["llm","huggingface","ai"] },
    Rule { id: "huggingface-token-env",   description: "Hugging Face Token in env/config",  pattern: r"(?i)(?:HUGGING_FACE|HUGGINGFACE)[._-]?(?:HUB[._-]?)?TOKEN\s*[=:]\s*([A-Za-z0-9_\-]{20,})", secret_group: 1, severity: Severity::High, tags: vec!["llm","huggingface","ai"] },
    Rule { id: "replicate-api-key",       description: "Replicate API Token",               pattern: r"r8_[A-Za-z0-9]{32,}", secret_group: 0, severity: Severity::High, tags: vec!["llm","replicate","ai"] },
    Rule { id: "together-ai-key",         description: "Together AI API Key",               pattern: r"(?i)TOGETHER[._-]?API[._-]?KEY\s*[=:]\s*([A-Za-z0-9]{64})", secret_group: 1, severity: Severity::Critical, tags: vec!["llm","together","ai"] },
    Rule { id: "perplexity-api-key",      description: "Perplexity AI API Key",             pattern: r"pplx-[A-Za-z0-9]{48}", secret_group: 0, severity: Severity::High, tags: vec!["llm","perplexity","ai"] },
    Rule { id: "groq-api-key",            description: "Groq API Key",                      pattern: r"gsk_[A-Za-z0-9]{52}", secret_group: 0, severity: Severity::High, tags: vec!["llm","groq","ai"] },
    Rule { id: "xai-api-key",            description: "xAI / Grok API Key",                pattern: r"xai-[A-Za-z0-9]{32,}", secret_group: 0, severity: Severity::Critical, tags: vec!["llm","xai","grok","ai"] },
    Rule { id: "azure-openai-key",        description: "Azure OpenAI API Key",              pattern: r"(?i)(?:AZURE[._-]?OPENAI[._-]?(?:API[._-]?)?KEY)\s*[=:]\s*([a-f0-9]{32})", secret_group: 1, severity: Severity::Critical, tags: vec!["llm","azure","openai","ai"] },
    Rule { id: "stability-ai-key",        description: "Stability AI API Key",              pattern: r"sk-[A-Za-z0-9]{48}[^A-Za-z0-9]", secret_group: 0, severity: Severity::High, tags: vec!["llm","stability","ai"] },

    // ── Azure / Entra ID / M365 ───────────────────────────────────────────────
    Rule {
        id: "azure-tenant-id",
        description: "Azure Tenant ID",
        pattern: r"(?i)(?:tenant[_-]?id|AZURE_TENANT_ID|tenantId)\s*[=:]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        secret_group: 1, severity: Severity::Medium, tags: vec!["azure","entra","m365"],
    },
    Rule {
        id: "azure-client-id",
        description: "Azure App Registration Client ID",
        pattern: r"(?i)(?:client[_-]?id|app[_-]?id|AZURE_CLIENT_ID|clientId|applicationId)\s*[=:]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        secret_group: 1, severity: Severity::Medium, tags: vec!["azure","entra","m365"],
    },
    Rule {
        id: "azure-client-secret",
        description: "Azure App Registration Client Secret",
        pattern: r"(?i)(?:client[_-]?secret|AZURE_CLIENT_SECRET|clientSecret)\s*[=:]\s*([A-Za-z0-9~._\-]{34,})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","entra","m365"],
    },
    Rule {
        id: "azure-subscription-key",
        description: "Azure API Management Subscription Key",
        pattern: r"(?i)(?:Ocp-Apim-Subscription-Key|subscription[_-]?key|APIM[_-]?KEY)\s*[=:]\s*([a-f0-9]{32})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","apim"],
    },
    Rule {
        id: "azure-storage-account-key",
        description: "Azure Storage Account Key",
        pattern: r"(?i)(?:AccountKey|AZURE_STORAGE_KEY|storageAccountKey)\s*[=:]\s*([A-Za-z0-9+/]{86}==)",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","storage"],
    },
    Rule {
        id: "azure-storage-connection-string",
        description: "Azure Storage Connection String",
        pattern: r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==[^;]*",
        secret_group: 0, severity: Severity::Critical, tags: vec!["azure","storage"],
    },
    Rule {
        id: "azure-sas-token",
        description: "Azure Shared Access Signature (SAS) Token",
        pattern: r"(?:sv|sig|se|sp)=[A-Za-z0-9%+/=&\-]{8,}(?:&(?:sv|sig|se|sp|spr|srt|ss)=[A-Za-z0-9%+/=&\-]{4,}){3,}",
        secret_group: 0, severity: Severity::Critical, tags: vec!["azure","sas","storage"],
    },
    Rule {
        id: "azure-function-key",
        description: "Azure Function App Key",
        pattern: r"(?i)(?:x-functions-key|AZURE_FUNCTION_KEY|functionKey)\s*[=:]\s*([A-Za-z0-9/+]{40,}={0,2})",
        secret_group: 1, severity: Severity::High, tags: vec!["azure","functions"],
    },
    Rule {
        id: "azure-service-bus-connstr",
        description: "Azure Service Bus Connection String",
        pattern: r"Endpoint=sb://[^;]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/]{43}=",
        secret_group: 0, severity: Severity::Critical, tags: vec!["azure","servicebus"],
    },
    Rule {
        id: "azure-eventhub-connstr",
        description: "Azure Event Hub Connection String",
        pattern: r"Endpoint=sb://[^;]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/]{43}=;EntityPath=[^\s]+",
        secret_group: 0, severity: Severity::Critical, tags: vec!["azure","eventhub"],
    },
    Rule {
        id: "azure-cosmosdb-key",
        description: "Azure Cosmos DB Account Key",
        pattern: r"(?i)(?:cosmos[._-]?(?:db[._-]?)?(?:account[._-]?)?key|COSMOS_KEY)\s*[=:]\s*([A-Za-z0-9+/]{86}==)",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","cosmosdb"],
    },
    Rule {
        id: "azure-search-admin-key",
        description: "Azure Cognitive Search Admin Key",
        pattern: r"(?i)(?:search[._-]?(?:admin[._-]?)?key|AZURE_SEARCH_KEY)\s*[=:]\s*([A-Za-z0-9]{32})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","search"],
    },
    Rule {
        id: "azure-cognitive-key",
        description: "Azure Cognitive Services Key",
        pattern: r"(?i)(?:cognitive[._-]?(?:services[._-]?)?key|AZURE_COGNITIVE_KEY)\s*[=:]\s*([a-f0-9]{32})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["azure","cognitive","ai"],
    },
    Rule {
        id: "azure-iot-hub-connstr",
        description: "Azure IoT Hub Connection String",
        pattern: r"HostName=[^;]+\.azure-devices\.net;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/]{43}=",
        secret_group: 0, severity: Severity::Critical, tags: vec!["azure","iot"],
    },
    Rule {
        id: "sharepoint-client-secret",
        description: "SharePoint / M365 App Client Secret",
        pattern: r"(?i)(?:SharePoint|SPO|M365)[._-]?(?:client[._-]?)?secret\s*[=:]\s*([A-Za-z0-9+/]{32,}={0,2})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["m365","sharepoint"],
    },
    Rule {
        id: "graph-api-client-secret",
        description: "Microsoft Graph API Client Secret",
        pattern: r"(?i)(?:graph[._-]?(?:api[._-]?)?(?:client[._-]?)?secret|MS_GRAPH_SECRET)\s*[=:]\s*([A-Za-z0-9~._\-]{34,})",
        secret_group: 1, severity: Severity::Critical, tags: vec!["m365","graph","azure"],
    },
    Rule {
        id: "teams-webhook",
        description: "Microsoft Teams Incoming Webhook URL",
        pattern: r"https://[a-zA-Z0-9\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@]+/IncomingWebhook/[A-Za-z0-9]+/[A-Za-z0-9\-]+",
        secret_group: 0, severity: Severity::High, tags: vec!["m365","teams","webhook"],
    },
    Rule {
        id: "power-automate-shared-key",
        description: "Power Automate / Logic Apps Shared Key",
        pattern: r"(?i)(?:LogicApp|PowerAutomate|flow)[._-]?(?:shared[._-]?)?(?:access[._-]?)?key\s*[=:]\s*([A-Za-z0-9+/]{40,}={0,2})",
        secret_group: 1, severity: Severity::High, tags: vec!["m365","power-automate","azure"],
    },

    // ── Frontend / SaaS ──────────────────────────────────────────────────────
    Rule { id: "firebase-private-key",   description: "Firebase Admin SDK Private Key ID",     pattern: r"(?i)(?:firebase|FIREBASE)[._-]?(?:admin[._-]?)?(?:private[._-]?)?key[._-]?(?:id)?\s*[=:]\s*([A-Za-z0-9]{40})", secret_group: 1, severity: Severity::Critical, tags: vec!["firebase","google","frontend"] },
    Rule { id: "mapbox-public-token",    description: "Mapbox Public Access Token",            pattern: r"pk\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+", secret_group: 0, severity: Severity::Low, tags: vec!["mapbox","frontend"] },
    Rule { id: "mapbox-secret-token",    description: "Mapbox Secret Access Token",            pattern: r"sk\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+", secret_group: 0, severity: Severity::High, tags: vec!["mapbox","frontend"] },
    Rule { id: "sentry-dsn",            description: "Sentry DSN (contains auth token)",      pattern: r"https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+", secret_group: 0, severity: Severity::Medium, tags: vec!["sentry","observability","frontend"] },
    Rule { id: "contentful-pat",         description: "Contentful Personal Access Token",      pattern: r"CFPAT-[A-Za-z0-9\-_]{43}", secret_group: 0, severity: Severity::High, tags: vec!["contentful","cms","frontend"] },
    Rule { id: "shopify-pat",            description: "Shopify Admin API Access Token",        pattern: r"shpat_[A-Fa-f0-9]{32}", secret_group: 0, severity: Severity::Critical, tags: vec!["shopify","ecommerce"] },
    Rule { id: "shopify-shared-secret",  description: "Shopify Shared Secret",                 pattern: r"shpss_[A-Fa-f0-9]{32}", secret_group: 0, severity: Severity::Critical, tags: vec!["shopify","ecommerce"] },
    Rule { id: "shopify-custom-app",     description: "Shopify Custom App Access Token",       pattern: r"shpca_[A-Fa-f0-9]{32}", secret_group: 0, severity: Severity::Critical, tags: vec!["shopify","ecommerce"] },
    Rule { id: "shopify-private-app",    description: "Shopify Private App Access Token",      pattern: r"shppa_[A-Fa-f0-9]{32}", secret_group: 0, severity: Severity::Critical, tags: vec!["shopify","ecommerce"] },
    Rule { id: "algolia-admin-key",      description: "Algolia Admin API Key",                 pattern: r#"(?i)(?:algolia[._-]?(?:admin[._-]?)?(?:api[._-]?)?key|ALGOLIA_ADMIN_KEY)\s*[=:]["'\s]*([a-f0-9]{32})"#, secret_group: 1, severity: Severity::Critical, tags: vec!["algolia","search","frontend"] },
    Rule { id: "linear-api-key",         description: "Linear API Key",                        pattern: r"lin_api_[A-Za-z0-9]{40}", secret_group: 0, severity: Severity::High, tags: vec!["linear","project-management"] },
    Rule { id: "postman-api-key",        description: "Postman API Key",                       pattern: r"PMAK-[A-Za-z0-9\-]{58,}", secret_group: 0, severity: Severity::High, tags: vec!["postman","api"] },
    Rule { id: "planetscale-token",      description: "PlanetScale API Token",                 pattern: r"pscale_tkn_[A-Za-z0-9\-_]{43}", secret_group: 0, severity: Severity::High, tags: vec!["planetscale","database","frontend"] },
    Rule { id: "cloudflare-api-token",   description: "Cloudflare API Token",                  pattern: r"(?i)(?:CF[._-]?API[._-]?TOKEN|CLOUDFLARE[._-]?(?:API[._-]?)?TOKEN)\s*[=:]\s*([A-Za-z0-9\-_]{40})", secret_group: 1, severity: Severity::High, tags: vec!["cloudflare","cdn","edge"] },
    Rule { id: "cloudflare-api-key",     description: "Cloudflare Global API Key",             pattern: r"(?i)(?:CF[._-]?API[._-]?KEY|CLOUDFLARE[._-]?(?:API[._-]?)?KEY)\s*[=:]\s*([a-f0-9]{37})", secret_group: 1, severity: Severity::Critical, tags: vec!["cloudflare","cdn","edge"] },

    // ── Datenbank ────────────────────────────────────────────────────────────
    Rule { id: "db-postgres-url",      description: "PostgreSQL Connection String",   pattern: r"postgres(?:ql)?://[^:@\s]+:[^:@\s]+@[^/\s]+/\S+",             secret_group: 0, severity: Severity::Critical, tags: vec!["database","postgres"] },
    Rule { id: "db-mysql-url",         description: "MySQL Connection String",        pattern: r"mysql(?:2)?://[^:@\s]+:[^:@\s]+@[^/\s]+/\S+",                secret_group: 0, severity: Severity::Critical, tags: vec!["database","mysql"] },
    Rule { id: "db-mongodb-url",       description: "MongoDB Connection String",      pattern: r"mongodb(?:\+srv)?://[^:@\s]+:[^:@\s]+@[^/\s]+(?:/\S*)?",     secret_group: 0, severity: Severity::Critical, tags: vec!["database","mongodb"] },
    Rule { id: "db-redis-url",         description: "Redis Connection String",        pattern: r"rediss?://(?:[^:@\s]+:)[^@\s]+@[^/\s]+(?:/\d+)?",            secret_group: 0, severity: Severity::High,     tags: vec!["database","redis"] },
    Rule { id: "db-mssql-connstr",     description: "MSSQL Connection String",        pattern: r"(?i)(?:Server|Data Source)=[^;]+;[^;]*(?:Password|PWD)=([^;]+)", secret_group: 1, severity: Severity::Critical, tags: vec!["database","mssql"] },
    Rule { id: "db-elasticsearch-url", description: "Elasticsearch URL with creds",  pattern: r"https?://[^:@\s]+:[^:@\s]+@[^/\s]*(?:920[0-9]|930[0-9])[^\s]*", secret_group: 0, severity: Severity::High,  tags: vec!["database","elasticsearch"] },
    Rule { id: "db-amqp-url",          description: "AMQP / RabbitMQ URL",           pattern: r"amqps?://[^:@\s]+:[^:@\s]+@[^/\s]+",                         secret_group: 0, severity: Severity::High,     tags: vec!["database","rabbitmq","amqp"] },
    Rule { id: "db-generic-password",  description: "Generic DB password in config",  pattern: r#"(?i)(?:db|database)[_\-\.]?(?:password|passwd|pwd)\s*[=:]\s*[^\s"']{8,}"#, secret_group: 0, severity: Severity::High, tags: vec!["database","generic"] },
    Rule { id: "db-jdbc-url",          description: "JDBC URL with credentials",     pattern: r"jdbc:[a-z0-9]+://[^:@\s]*:[^@\s]+@[^\s]+",                   secret_group: 0, severity: Severity::Critical, tags: vec!["database","jdbc"] },

    // ── OpenTelemetry / Observability ────────────────────────────────────────
    Rule { id: "otel-endpoint-with-auth", description: "OTLP endpoint with credentials",        pattern: r"https?://[^:@\s]+:[^:@\s]+@[^\s]*(?:4317|4318|otlp|otel|opentelemetry)[^\s]*", secret_group: 0, severity: Severity::High, tags: vec!["opentelemetry","otel"] },
    Rule { id: "otel-exporter-headers",   description: "OTLP exporter headers with auth token", pattern: r"(?i)OTEL_EXPORTER_OTLP_HEADERS\s*=\s*[^\n]*(?:api[_-]?key|authorization|x-honeycomb-team)=[A-Za-z0-9\-_+/=]{12,}", secret_group: 0, severity: Severity::High, tags: vec!["opentelemetry","otel"] },
    Rule { id: "honeycomb-api-key",       description: "Honeycomb API Key",                     pattern: r"(?i)(?:x-honeycomb-team|honeycomb[._-]?(?:api[._-]?)?key)\s*[=:]\s*([A-Za-z0-9]{22,})", secret_group: 1, severity: Severity::High, tags: vec!["honeycomb","observability"] },
    Rule { id: "datadog-api-key",         description: "Datadog API Key",                       pattern: r"(?i)(?:DD_API_KEY|datadog[._-]?api[._-]?key)\s*[=:]\s*([a-f0-9]{32})", secret_group: 1, severity: Severity::High, tags: vec!["datadog","observability"] },
    Rule { id: "newrelic-license-key",    description: "New Relic License Key",                 pattern: r"(?i)(?:NEW_RELIC_LICENSE_KEY|newrelic[._-]?license[._-]?key)\s*[=:]\s*([A-Za-z0-9]{40})", secret_group: 1, severity: Severity::High, tags: vec!["newrelic","observability"] },
    Rule { id: "grafana-service-account", description: "Grafana Service Account Token",         pattern: r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}", secret_group: 0, severity: Severity::High, tags: vec!["grafana","observability"] },
    Rule { id: "lightstep-token",         description: "Lightstep Access Token",                pattern: r"(?i)(?:x-lightstep-access-token|lightstep[._-]?token)\s*[=:]\s*([A-Za-z0-9\-_]{20,})", secret_group: 1, severity: Severity::High, tags: vec!["lightstep","observability"] },

    // ── HTTP Basic Auth ──────────────────────────────────────────────────────
    Rule { id: "http-basic-auth-header", description: "HTTP Authorization: Basic header",   pattern: r"(?i)(?:Authorization|auth)\s*[:=]\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})", secret_group: 1, severity: Severity::High, tags: vec!["http","basic-auth"] },
    Rule { id: "http-basic-auth-curl",   description: "curl -u / --user with credentials", pattern: r#"curl\s+[^\n]*(?:-u|--user)\s+([^:'\s"]+:[^@'\s"]+)"#, secret_group: 1, severity: Severity::High, tags: vec!["http","basic-auth","curl"] },
    Rule { id: "http-basic-auth-env",    description: "Basic Auth credentials in env var",  pattern: r"(?i)BASIC[_-]?AUTH\s*[=:]\s*([A-Za-z0-9+/]{8,}={0,2})", secret_group: 1, severity: Severity::High, tags: vec!["http","basic-auth"] },

    // ── HTTP Bearer Token ────────────────────────────────────────────────────
    Rule { id: "http-bearer-header", description: "HTTP Authorization: Bearer token",  pattern: r"(?i)(?:Authorization|auth)\s*[:=]\s*Bearer\s+([A-Za-z0-9\-_=+/.]{16,})", secret_group: 1, severity: Severity::High, tags: vec!["http","bearer"] },
    Rule { id: "http-bearer-env",    description: "Bearer token in env var",           pattern: r"(?i)BEARER[_-]?TOKEN\s*[=:]\s*([A-Za-z0-9\-_=+/.]{16,})", secret_group: 1, severity: Severity::High, tags: vec!["http","bearer"] },
    Rule { id: "http-bearer-curl",   description: "curl -H Authorization: Bearer",    pattern: r#"(?i)curl\s+[^\n]*-H\s+"Authorization:\s*Bearer\s+([A-Za-z0-9\-_=+/.]{16,})""#, secret_group: 1, severity: Severity::High, tags: vec!["http","bearer","curl"] },

    // ── HTTP Warnings ────────────────────────────────────────────────────────
    Rule { id: "http-insecure-url",    description: "Insecure HTTP URL (prefer HTTPS)",              pattern: r"http://[a-zA-Z0-9\-._~:/?#\[\]@!$&()*+,;=%]{4,}", secret_group: 0, severity: Severity::Warning,  tags: vec!["http","insecure"] },
    Rule { id: "http-auth-over-http",  description: "Credentials sent over plain HTTP",              pattern: r"(?i)http://[^:@\s]+:[^:@\s]+@[^\s]+",            secret_group: 0, severity: Severity::Critical, tags: vec!["http","insecure","credentials"] },

    // ── Infrastructure / CI ──────────────────────────────────────────────────
    Rule { id: "vault-service-token",      description: "HashiCorp Vault Service Token",      pattern: r"hvs\.[A-Za-z0-9_-]{24,}",                                                                                                                          secret_group: 0, severity: Severity::Critical, tags: vec!["vault","hashicorp","infra"] },
    Rule { id: "vault-batch-token",        description: "HashiCorp Vault Batch Token",         pattern: r"hvb\.[A-Za-z0-9_-]{24,}",                                                                                                                          secret_group: 0, severity: Severity::Critical, tags: vec!["vault","hashicorp","infra"] },
    Rule { id: "terraform-cloud-token",    description: "Terraform Cloud API Token",           pattern: r"TFC-[A-Za-z0-9]{14,}",                                                                                                                             secret_group: 0, severity: Severity::Critical, tags: vec!["terraform","hashicorp","infra"] },
    Rule { id: "digitalocean-pat",         description: "DigitalOcean Personal Access Token",  pattern: r"dop_v1_[a-f0-9]{64}",                                                                                                                              secret_group: 0, severity: Severity::Critical, tags: vec!["digitalocean","cloud"] },
    Rule { id: "circleci-token",           description: "CircleCI API Token",                  pattern: r"ccipat_[A-Za-z0-9]{40,}",                                                                                                                          secret_group: 0, severity: Severity::High,     tags: vec!["circleci","ci"] },

    // ── Email ────────────────────────────────────────────────────────────────
    Rule { id: "resend-api-key",           description: "Resend API Key",                      pattern: r"re_[A-Za-z0-9_-]{24,}",                                                                                                                            secret_group: 0, severity: Severity::High,     tags: vec!["resend","email"] },
    Rule { id: "mailgun-api-key",          description: "Mailgun API Key",                     pattern: r"\bkey-[a-f0-9]{32}\b",                                                                                                                             secret_group: 0, severity: Severity::High,     tags: vec!["mailgun","email"] },
    Rule { id: "postmark-server-token",    description: "Postmark Server API Token",           pattern: r"(?i)(?:POSTMARK[._-]?(?:SERVER[._-]?)?(?:API[._-]?)?TOKEN|X-Postmark-Server-Token)\s*[=:]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", secret_group: 1, severity: Severity::High,     tags: vec!["postmark","email"] },

    // ── Datenbank / BaaS ─────────────────────────────────────────────────────
    Rule { id: "supabase-pat",             description: "Supabase Personal Access Token",      pattern: r"sbp_[a-f0-9]{40}",                                                                                                                                 secret_group: 0, severity: Severity::Critical, tags: vec!["supabase","database"] },
    Rule { id: "supabase-service-role",    description: "Supabase Service Role Key (JWT)",     pattern: r"(?i)SUPABASE[._-]?(?:SERVICE[._-]?ROLE[._-]?)?KEY\s*[=:]\s*(eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{27,})",                    secret_group: 1, severity: Severity::Critical, tags: vec!["supabase","database","jwt"] },

    // ── AI / Embeddings ──────────────────────────────────────────────────────
    Rule { id: "pinecone-api-key",         description: "Pinecone API Key",                    pattern: r"pcsk_[A-Za-z0-9_]{40,}",                                                                                                                           secret_group: 0, severity: Severity::Critical, tags: vec!["pinecone","ai","embeddings"] },
    Rule { id: "elevenlabs-api-key",       description: "ElevenLabs API Key",                  pattern: r"(?i)(?:ELEVENLABS[._-]?(?:API[._-]?)?KEY|XI_API_KEY)\s*[=:]\s*([a-f0-9]{32})",                                                                    secret_group: 1, severity: Severity::High,     tags: vec!["elevenlabs","ai","voice"] },
    Rule { id: "openai-api-key-env",       description: "OpenAI API Key in env/config",        pattern: r"(?i)(?:OPENAI[._-]?API[._-]?KEY)\s*[=:]\s*(sk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{20,})",                                                           secret_group: 1, severity: Severity::Critical, tags: vec!["llm","openai","ai","python"] },
    Rule { id: "anthropic-api-key-env",    description: "Anthropic API Key in env/config",     pattern: r"(?i)(?:ANTHROPIC[._-]?API[._-]?KEY)\s*[=:]\s*(sk-ant-(?:api03-)?[A-Za-z0-9\-_]{16,})",                                                             secret_group: 1, severity: Severity::Critical, tags: vec!["llm","anthropic","ai","python"] },

    // ── Python / LLM Secret Leaks ────────────────────────────────────────────
    Rule { id: "python-llm-key-assignment", description: "Hardcoded LLM key/token in Python assignment", pattern: r#"(?i)\b(?:openai|anthropic|azure_openai|mistral|cohere|groq|together|huggingface|hf|replicate|perplexity|xai|langsmith|pinecone|weaviate)[._-]?(?:api[._-]?)?(?:key|token|secret)\b\s*=\s*["'][^"'\n]{16,}["']"#, secret_group: 0, severity: Severity::Critical, tags: vec!["python","llm","secret","ai"] },
    Rule { id: "python-dotenv-llm-key",     description: "LLM key/token in .env-style line", pattern: r"(?i)^\s*(?:OPENAI|ANTHROPIC|AZURE_OPENAI|MISTRAL|COHERE|GROQ|TOGETHER|HUGGINGFACE|HF|REPLICATE|PERPLEXITY|XAI|LANGSMITH|PINECONE|WEAVIATE)[A-Z0-9_]*_(?:API_)?(?:KEY|TOKEN|SECRET)\s*=\s*[^\s#]{16,}\s*$", secret_group: 0, severity: Severity::Critical, tags: vec!["python","llm","dotenv","secret"] },
    Rule { id: "langsmith-api-key-env",     description: "LangSmith/LangChain API key in env/config", pattern: r"(?i)\b(?:LANGSMITH|LANGCHAIN)[A-Z0-9_]*_(?:API_)?KEY\s*[=:]\s*([A-Za-z0-9_\-]{20,})",                                                    secret_group: 1, severity: Severity::Critical, tags: vec!["python","llm","langsmith","secret"] },
    Rule { id: "python-os-environ-secret",  description: "Secret injected via os.environ assignment", pattern: r#"(?i)\bos\.environ\[\s*["'][A-Z0-9_]*(?:API_)?(?:KEY|TOKEN|SECRET)[A-Z0-9_]*["']\s*\]\s*=\s*["'][^"'\n]{12,}["']"#, secret_group: 0, severity: Severity::High, tags: vec!["python","env","secret"] },
    Rule { id: "python-openai-client-inline-key", description: "Inline API key in OpenAI client init", pattern: r#"(?i)\bOpenAI\s*\(\s*api_key\s*=\s*["'][^"'\n]{16,}["']"#, secret_group: 0, severity: Severity::Critical, tags: vec!["python","openai","llm","secret"] },
    Rule { id: "python-anthropic-client-inline-key", description: "Inline API key in Anthropic client init", pattern: r#"(?i)\bAnthropic\s*\(\s*api_key\s*=\s*["'][^"'\n]{16,}["']"#, secret_group: 0, severity: Severity::Critical, tags: vec!["python","anthropic","llm","secret"] },
    Rule { id: "vertex-private-key-json",   description: "Vertex/GCP service account private key in JSON", pattern: r#""private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----"#,                                                                                   secret_group: 0, severity: Severity::Critical, tags: vec!["python","gcp","vertex","secret"] },
    Rule { id: "aws-bedrock-access-key-env", description: "AWS access key in env/config (Bedrock capable)", pattern: r"(?i)\bAWS_ACCESS_KEY_ID\s*[=:]\s*((?:AKIA|ASIA)[A-Z0-9]{16})",                                                                      secret_group: 1, severity: Severity::Critical, tags: vec!["python","aws","bedrock","secret"] },
    Rule { id: "aws-bedrock-secret-key-env", description: "AWS secret access key in env/config (Bedrock capable)", pattern: r"(?i)\bAWS_SECRET_ACCESS_KEY\s*[=:]\s*([A-Za-z0-9/+=]{40})",                                                                   secret_group: 1, severity: Severity::Critical, tags: vec!["python","aws","bedrock","secret"] },
    Rule { id: "streamlit-secrets-llm-key", description: "LLM key in Streamlit secrets.toml style", pattern: r#"(?i)\b(?:openai|anthropic|langsmith|cohere|mistral|groq|together|huggingface|replicate|perplexity|xai)[._-]?(?:api[._-]?)?(?:key|token|secret)\s*=\s*["'][^"'\n]{16,}["']"#, secret_group: 0, severity: Severity::Critical, tags: vec!["python","streamlit","llm","secret"] },

    // ── Communication ────────────────────────────────────────────────────────
    Rule { id: "slack-signing-secret",     description: "Slack Signing Secret",                pattern: r"(?i)(?:SLACK_SIGNING_SECRET|slack[._-]?signing[._-]?secret)\s*[=:]\s*([a-f0-9]{32})",                                                              secret_group: 1, severity: Severity::High,     tags: vec!["slack","communication"] },
    Rule { id: "slack-app-token",          description: "Slack App-Level Token",               pattern: r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{64}",                                                                                                        secret_group: 0, severity: Severity::High,     tags: vec!["slack","communication"] },
    Rule { id: "twilio-auth-token",        description: "Twilio Auth Token",                   pattern: r"(?i)TWILIO[._-]?AUTH[._-]?TOKEN\s*[=:]\s*([a-f0-9]{32})",                                                                                         secret_group: 1, severity: Severity::Critical, tags: vec!["twilio","communication"] },
    Rule { id: "discord-bot-token",        description: "Discord Bot Token",                   pattern: r"(?i)(?:discord[._-]?(?:bot[._-]?)?token|DISCORD_TOKEN)\s*[=:]\s*([A-Za-z0-9_-]{24,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})",                   secret_group: 1, severity: Severity::High,     tags: vec!["discord","communication"] },
    Rule { id: "telegram-bot-token",       description: "Telegram Bot Token",                  pattern: r"[0-9]{8,12}:[A-Za-z0-9_-]{35}",                                                                                                                   secret_group: 0, severity: Severity::High,     tags: vec!["telegram","communication"] },
    Rule { id: "notion-integration-token", description: "Notion Integration Token",            pattern: r"secret_[A-Za-z0-9]{43}",                                                                                                                           secret_group: 0, severity: Severity::High,     tags: vec!["notion","communication"] },
    Rule { id: "notion-oauth-token",       description: "Notion OAuth Access Token",           pattern: r"ntn_[A-Za-z0-9]{40,}",                                                                                                                             secret_group: 0, severity: Severity::High,     tags: vec!["notion","communication"] },

    // ── GCP ──────────────────────────────────────────────────────────────────
    Rule { id: "gcp-service-account",      description: "GCP Service Account JSON",            pattern: r#""type"\s*:\s*"service_account""#,                                                                                                                  secret_group: 0, severity: Severity::Critical, tags: vec!["gcp","google","cloud"] },
]}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn all_patterns_compile() {
        for rule in builtin_rules() {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "Pattern failed to compile for rule: {}", rule.id
            );
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let rules = builtin_rules();
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            assert!(seen.insert(rule.id), "Duplicate rule ID: {}", rule.id);
        }
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::High.to_string(),     "HIGH");
        assert_eq!(Severity::Medium.to_string(),   "MEDIUM");
        assert_eq!(Severity::Low.to_string(),      "LOW");
        assert_eq!(Severity::Warning.to_string(),  "WARNING");
    }
}
