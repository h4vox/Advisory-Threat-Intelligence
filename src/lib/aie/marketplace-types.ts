/**
 * Marketplace & Response Integration Types
 *
 * Defines the data models for external agent integrations (AGY, Claude Code, Codex),
 * direct AI API providers (Gemini, Claude), curated intelligence feeds,
 * powerups, and adversary emulation playbooks.
 */

export type IntegrationCategory =
  | "Intelligence"
  | "Analysis"
  | "Automation"
  | "Playbooks";

export type IntegrationType = "cli_agent" | "api_provider" | "plugin" | "feed";

export type IntegrationStatus = "installed" | "not_installed" | "installing" | "error";

export type IntegrationAction = {
  id: string;
  name: string;
  description: string;
};

export type IntegrationConnector = {
  type: "oauth_cli" | "api_key" | "binary" | "webhook" | "rss_json";
  label: string;
  description: string;
  authUrl?: string;
  requiredEnvVar?: string;
};

export type IntegrationItem = {
  id: string;
  name: string;
  category: IntegrationCategory;
  type: IntegrationType;
  provider: string;
  version: string;
  releaseDate: string;
  status: IntegrationStatus;
  isDefault?: boolean;
  description: string;
  overview: string;
  installCommand?: string;
  authUrl?: string;
  actions: IntegrationAction[];
  connectors: IntegrationConnector[];
  tags: string[];
  supportedModels: string[];
  config?: {
    apiKey?: string;
    authToken?: string;
    customBinaryPath?: string;
    selectedModel?: string;
    installedAt?: string;
    lastTestedAt?: string;
    isConfigured?: boolean;
  };
};

export type CuratedResourceCatalogItem = {
  id: string;
  name: string;
  provider: string;
  category: string;
  description: string;
  endpointUrl: string;
  format: "RSS/Atom" | "JSON-LD" | "PDF Repository" | "STIX 2.1";
  cadence: "Real-time" | "Daily" | "Weekly";
  trustScore: number;
  status: "active" | "available";
  tags: string[];
};

export type PowerupItem = {
  id: string;
  name: string;
  author: string;
  category: "Exporters" | "Alerting" | "Enrichment" | "Automation";
  description: string;
  version: string;
  status: "installed" | "available";
  tags: string[];
};

export type PlaybookBlockItem = {
  id: string;
  name: string;
  framework: "Atomic Red Team" | "MITRE ATT&CK" | "CALDERA" | "Custom AIE";
  tactics: string[];
  techniques: string[];
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  description: string;
  status: "ready" | "available";
  stepsCount: number;
  tags: string[];
};

export type MarketplaceState = {
  activeProviderId: string;
  activeModel: string;
  integrations: IntegrationItem[];
  curatedResources: CuratedResourceCatalogItem[];
  powerups: PowerupItem[];
  playbooks: PlaybookBlockItem[];
};
