import type { RuleCategory, SecurityRule } from '../types/rule.js';

export class RuleRegistry {
  private rules: Map<string, SecurityRule> = new Map();

  /**
   * Registers a security rule. Throws an error if a rule with the same ID is already registered.
   */
  public register(rule: SecurityRule): void {
    if (this.rules.has(rule.id)) {
      throw new Error(`Rule with ID "${rule.id}" is already registered.`);
    }
    this.rules.set(rule.id, rule);
  }

  /**
   * Retrieves a rule by its ID.
   */
  public get(id: string): SecurityRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Returns all registered rules in insertion order.
   */
  public getAll(): SecurityRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Filters registered rules by functional category.
   */
  public getByCategory(category: RuleCategory): SecurityRule[] {
    return this.getAll().filter((rule) => rule.category === category);
  }

  /**
   * Clears all registered rules (useful in testing).
   */
  public clear(): void {
    this.rules.clear();
  }
}

/** Global default registry instance */
export const defaultRegistry = new RuleRegistry();
