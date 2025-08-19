import { describe, it, expect, beforeEach } from "vitest";

interface Threat {
  submitter: string;
  encryptedData: Uint8Array;
  metadata: {
    severity: bigint;
    affectedSystems: string;
    proofOfConcept: Uint8Array | null;
    description: string;
    timestamp: bigint;
  };
  status: bigint;
  revealedTo: string[];
  isRevealed: boolean;
}

const mockContract = {
  admin: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM" as string,
  paused: false as boolean,
  threatCounter: 0n as bigint,
  verifier: null as string | null,
  threats: new Map<bigint, Threat>(),
  submitterThreats: new Map<string, bigint[]>(),
  SEVERITY_LOW: 1n,
  SEVERITY_MEDIUM: 2n,
  SEVERITY_HIGH: 3n,
  SEVERITY_CRITICAL: 4n,
  STATUS_PENDING: 0n,
  STATUS_VERIFIED: 1n,
  STATUS_REJECTED: 2n,
  STATUS_REWARDED: 3n,

  isAdmin(caller: string): boolean {
    return caller === this.admin;
  },

  isVerifier(caller: string): boolean {
    return this.verifier !== null && caller === this.verifier;
  },

  setPaused(caller: string, pause: boolean): { value: boolean } | { error: number } {
    if (!this.isAdmin(caller)) return { error: 100 };
    this.paused = pause;
    return { value: pause };
  },

  setVerifier(caller: string, verifier: string): { value: boolean } | { error: number } {
    if (!this.isAdmin(caller)) return { error: 100 };
    this.verifier = verifier;
    return { value: true };
  },

  submitThreat(
    caller: string,
    encryptedData: Uint8Array,
    severity: bigint,
    affectedSystems: string,
    proofOfConcept: Uint8Array | null,
    description: string
  ): { value: bigint } | { error: number } {
    if (this.paused) return { error: 104 };
    if (encryptedData.length === 0) return { error: 111 };
    if (
      severity !== this.SEVERITY_LOW &&
      severity !== this.SEVERITY_MEDIUM &&
      severity !== this.SEVERITY_HIGH &&
      severity !== this.SEVERITY_CRITICAL
    ) return { error: 106 };
    if (affectedSystems.length === 0 || description.length === 0) return { error: 109 };

    const threatId = this.threatCounter + 1n;
    const threat: Threat = {
      submitter: caller,
      encryptedData,
      metadata: {
        severity,
        affectedSystems,
        proofOfConcept,
        description,
        timestamp: 100n, // Mock block-height
      },
      status: this.STATUS_PENDING,
      revealedTo: [],
      isRevealed: false,
    };
    this.threats.set(threatId, threat);

    const currentSubmissions = this.submitterThreats.get(caller) || [];
    this.submitterThreats.set(caller, [...currentSubmissions, threatId]);

    this.threatCounter = threatId;
    return { value: threatId };
  },

  updateStatus(
    caller: string,
    threatId: bigint,
    newStatus: bigint
  ): { value: boolean } | { error: number } {
    if (!this.isAdmin(caller) && !this.isVerifier(caller)) return { error: 100 };
    if (
      newStatus !== this.STATUS_VERIFIED &&
      newStatus !== this.STATUS_REJECTED &&
      newStatus !== this.STATUS_REWARDED
    ) return { error: 107 };
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    this.threats.set(threatId, { ...threat, status: newStatus });
    return { value: true };
  },

  grantAccess(
    caller: string,
    threatId: bigint,
    to: string
  ): { value: boolean } | { error: number } {
    if (!this.isAdmin(caller) && !this.isVerifier(caller)) return { error: 100 };
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    if (threat.revealedTo.length >= 10) return { error: 101 };
    this.threats.set(threatId, {
      ...threat,
      revealedTo: [...threat.revealedTo, to],
    });
    return { value: true };
  },

  revealData(
    caller: string,
    threatId: bigint
  ): { value: Uint8Array } | { error: number } {
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    if (
      !this.isAdmin(caller) &&
      !this.isVerifier(caller) &&
      !threat.revealedTo.includes(caller)
    ) return { error: 108 };
    return { value: threat.encryptedData };
  },

  markRevealed(
    caller: string,
    threatId: bigint
  ): { value: boolean } | { error: number } {
    if (!this.isAdmin(caller) && !this.isVerifier(caller)) return { error: 100 };
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    if (threat.isRevealed) return { error: 103 };
    this.threats.set(threatId, { ...threat, isRevealed: true });
    return { value: true };
  },

  getThreatMetadata(threatId: bigint): { value: Threat["metadata"] } | { error: number } {
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    return { value: threat.metadata };
  },

  getThreatStatus(threatId: bigint): { value: bigint } | { error: number } {
    const threat = this.threats.get(threatId);
    if (!threat) return { error: 102 };
    return { value: threat.status };
  },
};

describe("CyberGuard Threat Submission Contract", () => {
  beforeEach(() => {
    mockContract.admin = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
    mockContract.paused = false;
    mockContract.threatCounter = 0n;
    mockContract.verifier = null;
    mockContract.threats = new Map();
    mockContract.submitterThreats = new Map();
  });

  it("should submit a new threat successfully", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    const result = mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    expect(result).toEqual({ value: 1n });
    expect(mockContract.threats.size).toBe(1);
    expect(mockContract.submitterThreats.get("ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1")).toEqual([1n]);
  });

  it("should prevent submission with invalid severity", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    const result = mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      5n,
      "System X",
      null,
      "Test description"
    );
    expect(result).toEqual({ error: 106 });
  });

  it("should update status when called by verifier", () => {
    mockContract.setVerifier(mockContract.admin, "ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP");
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    const result = mockContract.updateStatus("ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP", 1n, 1n);
    expect(result).toEqual({ value: true });
    expect(mockContract.getThreatStatus(1n)).toEqual({ value: 1n });
  });

  it("should grant access to a principal", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    const result = mockContract.grantAccess(
      mockContract.admin,
      1n,
      "ST4JTJN9HZKZKAR0DWT6RTBRP2FZSYAQM69XT8PRV"
    );
    expect(result).toEqual({ value: true });
    const threat = mockContract.threats.get(1n);
    expect(threat?.revealedTo).toContain("ST4JTJN9HZKZKAR0DWT6RTBRP2FZSYAQM69XT8PRV");
  });

  it("should allow revealing data to granted principal", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    mockContract.grantAccess(
      mockContract.admin,
      1n,
      "ST4JTJN9HZKZKAR0DWT6RTBRP2FZSYAQM69XT8PRV"
    );
    const result = mockContract.revealData("ST4JTJN9HZKZKAR0DWT6RTBRP2FZSYAQM69XT8PRV", 1n);
    expect(result).toEqual({ value: encryptedData });
  });

  it("should deny revealing data to unauthorized principal", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    const result = mockContract.revealData("ST5RANDOM", 1n);
    expect(result).toEqual({ error: 108 });
  });

  it("should mark threat as revealed", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    const result = mockContract.markRevealed(mockContract.admin, 1n);
    expect(result).toEqual({ value: true });
    const threat = mockContract.threats.get(1n);
    expect(threat?.isRevealed).toBe(true);
  });

  it("should not allow marking already revealed threat", () => {
    const encryptedData = new Uint8Array([1, 2, 3]);
    mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    mockContract.markRevealed(mockContract.admin, 1n);
    const result = mockContract.markRevealed(mockContract.admin, 1n);
    expect(result).toEqual({ error: 103 });
  });

  it("should prevent actions when paused", () => {
    mockContract.setPaused(mockContract.admin, true);
    const encryptedData = new Uint8Array([1, 2, 3]);
    const result = mockContract.submitThreat(
      "ST2CY5V39NHDP5P0C5ATX5F23PH186Z0B32NDDJB1",
      encryptedData,
      3n,
      "System X",
      null,
      "Test description"
    );
    expect(result).toEqual({ error: 104 });
  });
});