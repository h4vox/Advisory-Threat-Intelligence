/**
 * Agent Framework - Driver Registry
 *
 * Provides a dynamic registry for agent drivers. Decouples agent implementations
 * from the rest of the application so future agents (e.g. Anthropic CLI, OpenAI agent,
 * custom CTI microservice) can be added without modifying the core system or UI.
 */

import type { AgentDriver } from "./types";
import { ContainerizedCliAgentDriver } from "./containerized-driver";

class AgentDriverRegistry {
  private drivers = new Map<string, AgentDriver>();

  constructor() {
    // Register the default containerized CLI driver
    const defaultDriver = new ContainerizedCliAgentDriver();
    this.register(defaultDriver);
  }

  register(driver: AgentDriver): void {
    this.drivers.set(driver.id, driver);
  }

  get(id: string): AgentDriver | undefined {
    return this.drivers.get(id);
  }

  getAll(): AgentDriver[] {
    return Array.from(this.drivers.values());
  }

  has(id: string): boolean {
    return this.drivers.has(id);
  }
}

export const agentRegistry = new AgentDriverRegistry();

export function getAgentDriver(id: string): AgentDriver | undefined {
  return agentRegistry.get(id);
}

export function registerAgentDriver(driver: AgentDriver): void {
  agentRegistry.register(driver);
}

export function getAllAgentDrivers(): AgentDriver[] {
  return agentRegistry.getAll();
}
