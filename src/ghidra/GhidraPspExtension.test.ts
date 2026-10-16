import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  RegularFileCleanupFailure,
  RegularFileCancelled,
} from "../filesystem/OwnedRegularFile.js";
import type { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import * as regularFileModule from "../filesystem/RegularFile.js";
import {
  inspectGhidraPspExtension,
  resolveGhidraPspExtension,
} from "./GhidraPspExtension.js";
import type { AvailableGhidraInstallation } from "./GhidraInstallation.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import type { Result } from "../domain/result.js";

const setupExtension = async (root: string, version = "12.1.3") => {
  const files: Record<string, string> = {
    "Module.manifest": "",
    "extension.properties": `name=ghidra-allegrex\nversion=${version}\n`,
    "data/languages/allegrex.ldefs": "synthetic language definition",
    "data/languages/allegrex.sla": "synthetic compiled processor",
    "data/languages/allegrex.pspec": "synthetic processor specification",
    "data/languages/allegrex.cspec": "synthetic compiler specification",
    "lib/extension.jar": "synthetic loader artifact",
  };
  for (const [relative, content] of Object.entries(files)) {
    const fullPath = join(root, relative);
    await mkdir(dirname(fullPath), { recursive: true });
    await writeFile(fullPath, content);
  }
};

const makeAvailableInstallation = (
  installDir: string,
): AvailableGhidraInstallation => ({
  status: "available",
  platform: "linux",
  architecture: "x64",
  installDir,
  analyzeHeadlessPath: join(installDir, "support", "analyzeHeadless"),
  applicationPropertiesPath: join(
    installDir,
    "Ghidra",
    "application.properties",
  ),
  providerVersion: "12.1.3",
  javaHome: "/jdk-21",
  javaVersion: "21.0.12",
  configurationDirectoryName: "ghidra_12.1.3",
  nativeDecompilerPath: join(
    installDir,
    "Ghidra",
    "Features",
    "Decompiler",
    "os",
    "linux_x86_64",
    "decompile",
  ),
  javaCommand: "java",
  checks: [],
});

describe("inspectGhidraPspExtension", () => {
  it("successfully inspects a valid Allegrex extension and hashes contents", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "ghidra-allegrex");
    await setupExtension(root, "12.1.3");

    const extension = await inspectGhidraPspExtension(root, "12.1.3");
    expect(extension.id).toBe("ghidra-allegrex");
    expect(extension.root).toBe(root);
    expect(extension.ghidra_version).toBe("12.1.3");
    expect(extension.sha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("preserves primary read failure and retains descriptor owner when close rejects", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "ghidra-allegrex");
    await setupExtension(root, "12.1.3");

    const readError = new Error("Disk I/O error during read");
    const closeError = new Error("Handle close failure");
    let retainedOwner: OwnedFileHandle | undefined;
    let closeSpy: ReturnType<typeof vi.spyOn> | undefined;

    const realOpen = regularFileModule.openRegularFile;
    const openSpy = vi
      .spyOn(regularFileModule, "openRegularFile")
      .mockImplementation(async (path, opts) => {
        const handle = await realOpen(path, opts);
        if (path.endsWith("extension.properties")) {
          vi.spyOn(handle, "read").mockRejectedValue(readError);
          closeSpy = vi.spyOn(handle, "close").mockRejectedValue(closeError);
        }
        return handle;
      });

    try {
      let thrown: unknown;
      try {
        await inspectGhidraPspExtension(root, "12.1.3", {
          retainFailedClose: (owner) => {
            retainedOwner = owner;
          },
        });
      } catch (err) {
        thrown = err;
      }

      expect(thrown).toBeInstanceOf(RegularFileCleanupFailure);
      const cleanupFailure = thrown as RegularFileCleanupFailure;
      expect(cleanupFailure.outcome.kind).toBe("failed");
      if (cleanupFailure.outcome.kind !== "failed")
        throw new Error("Expected failed outcome");
      expect(cleanupFailure.outcome.cause).toBe(readError);
      expect(cleanupFailure.cleanupCause).toBe(closeError);
      expect(retainedOwner).toBeDefined();
      expect(retainedOwner).toBe(cleanupFailure.owner);
    } finally {
      openSpy.mockRestore();
      closeSpy?.mockRestore();
      if (retainedOwner !== undefined) {
        await retainedOwner.close().catch(() => {});
      }
    }
  });

  it("supports backwards-compatible signal argument in inspectGhidraPspExtension", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "ghidra-allegrex");
    await setupExtension(root, "12.1.3");

    const controller = new AbortController();
    controller.abort();

    await expect(
      inspectGhidraPspExtension(root, "12.1.3", controller.signal),
    ).rejects.toThrow();
  });
});

describe("resolveGhidraPspExtension", () => {
  it("resolves Ghidra PSP extension successfully when installation is available", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const result = await resolveGhidraPspExtension(installation);
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(result.value.id).toBe("ghidra-allegrex");
    expect(result.value.ghidra_version).toBe("12.1.3");
  });

  it("preserves primary failure in userMessage and attaches cleanup when close rejects in resolveGhidraPspExtension", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const readError = new Error("Corrupted component bytes");
    const closeError = new Error("Descriptor leak on close");
    let retainedOwner: OwnedFileHandle | undefined;
    let closeSpy: ReturnType<typeof vi.spyOn> | undefined;

    const realOpen = regularFileModule.openRegularFile;
    const openSpy = vi
      .spyOn(regularFileModule, "openRegularFile")
      .mockImplementation(async (path, opts) => {
        const handle = await realOpen(path, opts);
        if (path.endsWith("allegrex.sla")) {
          vi.spyOn(handle, "read").mockRejectedValue(readError);
          closeSpy = vi.spyOn(handle, "close").mockRejectedValue(closeError);
        }
        return handle;
      });

    try {
      const result = await resolveGhidraPspExtension(installation, {
        retainFailedClose: (owner) => {
          retainedOwner = owner;
        },
      });

      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected failure");
      expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
      const capError = result.error as AnalysisCapabilityUnavailableError;
      // Primary cause must be cited in userMessage, NOT the close error
      expect(capError.userMessage).toContain("Corrupted component bytes");
      expect(capError.userMessage).not.toContain("Descriptor leak on close");
      // Cleanup metadata must be attached
      expect(capError.cleanup).toBeDefined();
      expect(capError.cleanup?.resources[0]).toContain("allegrex.sla");
      expect(retainedOwner).toBeDefined();
    } finally {
      openSpy.mockRestore();
      closeSpy?.mockRestore();
      if (retainedOwner !== undefined) {
        await retainedOwner.close().catch(() => {});
      }
    }
  });

  it("does not substitute cancellation for real producer failures when signal aborts after failure", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const controller = new AbortController();

    const realOpen = regularFileModule.openRegularFile;
    const openSpy = vi
      .spyOn(regularFileModule, "openRegularFile")
      .mockImplementation(async (path, opts) => {
        const handle = await realOpen(path, opts);
        try {
          // Abort signal concurrently/post failure
          controller.abort(new Error("Late abort"));
          throw new Error("Simulated producer read failure");
        } finally {
          await handle.close();
        }
      });

    try {
      const result = await resolveGhidraPspExtension(installation, {
        signal: controller.signal,
      });

      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected failure");
      // Must NOT be AnalysisCancelledError because the failure was a real producer error
      expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
      expect(result.error.message).toContain("Simulated producer read failure");
    } finally {
      openSpy.mockRestore();
    }
  });

  it("returns AnalysisCancelledError when operation is genuinely cancelled", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const controller = new AbortController();
    controller.abort(new Error("User cancelled"));

    const result = await resolveGhidraPspExtension(
      installation,
      controller.signal,
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected failure");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect((result.error as AnalysisCancelledError).operation).toBe(
      "resolve_analysis_profile",
    );
  });
});

describe("resolveGhidraPspExtension cancellation and cleanup", () => {
  it("retains the descriptor owner in error cause when cancelled during read without retention callback", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const controller = new AbortController();
    const closeError = new Error("Descriptor leak on close");
    let closeSpy: ReturnType<typeof vi.spyOn> | undefined;

    const realOpen = regularFileModule.openRegularFile;
    const openSpy = vi
      .spyOn(regularFileModule, "openRegularFile")
      .mockImplementation(async (path, opts) => {
        const handle = await realOpen(path, opts);
        if (path.endsWith("allegrex.sla")) {
          vi.spyOn(handle, "read").mockImplementation(async () => {
            controller.abort(new Error("User cancellation during read"));
            throw controller.signal.reason;
          });
          closeSpy = vi.spyOn(handle, "close").mockRejectedValue(closeError);
        }
        return handle;
      });

    let result: Result<unknown, unknown> | undefined;
    try {
      result = await resolveGhidraPspExtension(installation, controller.signal);

      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected failure");
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
      const cancelError = result.error as AnalysisCancelledError;
      expect(cancelError.operation).toBe("resolve_analysis_profile");
      expect(cancelError.cleanup).toBeDefined();
      expect(cancelError.cleanup?.resources[0]).toContain("allegrex.sla");

      // Verify the cleanup wrapper is preserved as cause, keeping the owner
      expect(cancelError.cause).toBeInstanceOf(RegularFileCleanupFailure);
      const cleanupFailure = cancelError.cause as RegularFileCleanupFailure;
      expect(cleanupFailure.owner).toBeDefined();
      expect(cleanupFailure.cleanupCause).toBe(closeError);
    } finally {
      openSpy.mockRestore();
      closeSpy?.mockRestore();
      if (
        result?.ok === false &&
        result.error instanceof AnalysisCancelledError &&
        result.error.cause instanceof RegularFileCleanupFailure
      ) {
        await result.error.cause.owner.close().catch(() => {});
      }
    }
  });

  it("returns AnalysisCancelledError with cleanup metadata when cancellation interrupts read and close also fails", async () => {
    const directory = await createTestTempDirectory("rea-psp-test-");
    const root = join(directory, "Ghidra", "Extensions", "ghidra-allegrex");
    await setupExtension(root, "12.1.3");
    const installation = makeAvailableInstallation(directory);

    const controller = new AbortController();
    const closeError = new Error("Descriptor leak on close");
    let retainedOwner: OwnedFileHandle | undefined;
    let closeSpy: ReturnType<typeof vi.spyOn> | undefined;

    const realOpen = regularFileModule.openRegularFile;
    const openSpy = vi
      .spyOn(regularFileModule, "openRegularFile")
      .mockImplementation(async (path, opts) => {
        const handle = await realOpen(path, opts);
        if (path.endsWith("allegrex.sla")) {
          vi.spyOn(handle, "read").mockImplementation(async () => {
            controller.abort(new Error("User cancellation during read"));
            throw controller.signal.reason;
          });
          closeSpy = vi.spyOn(handle, "close").mockRejectedValue(closeError);
        }
        return handle;
      });

    try {
      const result = await resolveGhidraPspExtension(installation, {
        signal: controller.signal,
        retainFailedClose: (owner) => {
          retainedOwner = owner;
        },
      });

      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected failure");
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
      const cancelError = result.error as AnalysisCancelledError;
      expect(cancelError.operation).toBe("resolve_analysis_profile");
      expect(cancelError.cleanup).toBeDefined();
      expect(cancelError.cleanup?.resources[0]).toContain("allegrex.sla");
      expect(retainedOwner).toBeDefined();
    } finally {
      openSpy.mockRestore();
      closeSpy?.mockRestore();
      if (retainedOwner !== undefined) {
        await retainedOwner.close().catch(() => {});
      }
    }
  });
});
