import { expect } from 'chai';
import { Contract, ethers } from 'ethers';
import { types } from '@abacus-network/utils';
import { AbacusApp, ProxiedAddress } from '@abacus-network/sdk';

export enum ViolationType {
  UpgradeBeacon = 'UpgradeBeacon',
  ValidatorManager = 'ValidatorManager',
  Validator = 'Validator',
}

export interface UpgradeBeaconViolation {
  domain: number;
  name: string;
  type: ViolationType.UpgradeBeacon;
  proxiedAddress: ProxiedAddress;
  expected: string;
  actual: string;
}

export interface ValidatorManagerViolation {
  domain: number;
  type: ViolationType.ValidatorManager;
  expected: string;
  actual: string;
}

export interface ValidatorViolation {
  local: number;
  remote: number;
  type: ViolationType.Validator;
  expected: string;
  actual: string;
}

export type Violation =
  | UpgradeBeaconViolation
  | ValidatorViolation
  | ValidatorManagerViolation;

export type VerificationInput = [string, Contract];

export abstract class AbacusAppChecker<A extends AbacusApp<any, any>, C> {
  readonly app: A;
  readonly config: C;
  readonly owners: Record<types.Domain, types.Address>;
  readonly violations: Violation[];

  abstract checkDomain(domain: types.Domain): Promise<void>;
  abstract checkOwnership(domain: types.Domain): Promise<void>;

  constructor(app: A, config: C, owners: Record<types.Domain, types.Address>) {
    this.app = app;
    this.config = config;
    this.owners = owners;
    this.violations = [];
  }

  async check(): Promise<void> {
    await Promise.all(
      this.app.domainNumbers.map((domain: types.Domain) =>
        this.checkDomain(domain),
      ),
    );
  }

  addViolation(v: Violation) {
    switch (v.type) {
      case ViolationType.UpgradeBeacon:
        const duplicateIndex = this.violations.findIndex(
          (m: Violation) =>
            m.type === ViolationType.UpgradeBeacon &&
            m.domain === v.domain &&
            m.actual === v.actual &&
            m.expected === v.expected,
        );
        if (duplicateIndex === -1) this.violations.push(v);
        break;
      default:
        this.violations.push(v);
        break;
    }
  }

  async checkProxiedContract(
    domain: types.Domain,
    name: string,
    proxiedAddress: ProxiedAddress,
  ) {
    // TODO: This should check the correct upgrade beacon controller
    expect(proxiedAddress.beacon).to.not.be.undefined;
    expect(proxiedAddress.proxy).to.not.be.undefined;
    expect(proxiedAddress.implementation).to.not.be.undefined;

    const provider = this.app.mustGetProvider(domain);
    // Assert that the implementation is actually set
    const storageValue = await provider.getStorageAt(proxiedAddress.beacon, 0);
    const actual = ethers.utils.getAddress(storageValue.slice(26));
    const expected = proxiedAddress.implementation;

    if (actual != expected) {
      const violation: UpgradeBeaconViolation = {
        domain,
        type: ViolationType.UpgradeBeacon,
        name,
        proxiedAddress,
        actual,
        expected,
      };
      this.addViolation(violation);
    }
  }

  expectViolations(types: ViolationType[], expectedMatches: number[]) {
    // Every type should have exactly the number of expected matches.
    const actualMatches = types.map(
      (t) => this.violations.map((v) => v.type === t).filter(Boolean).length,
    );
    expect(actualMatches).to.deep.equal(expectedMatches);
    // Every violation should be matched by at least one partial.
    const unmatched = this.violations.map(
      (v) => types.map((t) => v.type === t).filter(Boolean).length,
    );
    expect(unmatched).to.not.include(0);
  }

  expectEmpty(): void {
    expect(this.violations).to.be.empty;
  }
}