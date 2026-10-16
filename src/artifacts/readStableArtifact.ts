import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import type { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import {
  withArtifactFileHandle,
  assertArtifactReadActive,
} from "./ArtifactFileOperation.js";

/** Exact physical read completed before descriptor finalization. */
export interface StableArtifactSnapshot {
  readonly bytes: Buffer;
  readonly sha256: string;
}

/** Positional read size; the whole file still lands in one buffer. */
const READ_CHUNK_BYTES = 1024 * 1024;

/** Filesystem boundary for stable reads, including deterministic replacement probes. */
export interface StableArtifactFileSystem {
  lstat(path: string): Promise<BigIntStats>;
  open(path: string, flags: number): Promise<FileHandle>;
}

const FILE_SYSTEM: StableArtifactFileSystem = {
  lstat: (path) => lstat(path, { bigint: true }),
  open,
};

const afterValidation = async <T>(
  path: string,
  stage: string,
  read: () => Promise<T>,
): Promise<T> => {
  try {
    return await read();
  } catch (cause) {
    if (
      cause instanceof Error &&
      "code" in cause &&
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(String(cause.code))
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed ${stage}: ${path}`,
        { cause },
      );
    throw cause;
  }
};

/** Read one bounded regular file and reject replacement or in-place changes. */
export const readStableArtifact = async (
  path: string,
  maximumBytes: number,
  signal?: AbortSignal,
  fileSystem: StableArtifactFileSystem = FILE_SYSTEM,
  resourceScope?: ArtifactResourceScope,
): Promise<StableArtifactSnapshot> => {
  assertArtifactReadActive(signal);
  const before = await fileSystem.lstat(path);
  if (!before.isFile() || before.isSymbolicLink())
    throw new ArtifactReaderFailure(
      "path",
      `Expected a regular file without a symlink: ${path}`,
    );
  if (before.size > BigInt(maximumBytes))
    throw new ArtifactReaderFailure(
      "limit",
      `Selected artifact exceeds ${String(maximumBytes)} bytes: ${path}`,
      { boundary: "file-size" },
    );
  const file = await afterValidation(path, "before open", () =>
    fileSystem.open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ),
  );
  return withArtifactFileHandle(
    path,
    file,
    resourceScope,
    signal,
    async (file) => {
      const initial = await file.stat({ bigint: true });
      if (
        !initial.isFile() ||
        initial.dev !== before.dev ||
        initial.ino !== before.ino
      )
        throw new ArtifactReaderFailure(
          "integrity",
          `Artifact changed before open: ${path}`,
        );
      // One buffer of the admitted size, filled by positional reads: peak
      // memory stays at the file size (a chunk list plus its concatenation
      // was ~2.5x the input).
      const expected = Number(initial.size);
      if (expected > maximumBytes)
        throw new ArtifactReaderFailure(
          "limit",
          `Selected artifact grew beyond its byte limit: ${path}`,
          { boundary: "file-size" },
        );
      const content = Buffer.alloc(expected);
      let count = 0;
      while (count < expected) {
        assertArtifactReadActive(signal);
        const { bytesRead } = await file.read(
          content,
          count,
          Math.min(READ_CHUNK_BYTES, expected - count),
          count,
        );
        if (bytesRead === 0) break; // shrank: the identity check below refuses it
        count += bytesRead;
      }
      // Bytes past the admitted size mean the file grew during the read.
      const { bytesRead: extra } = await file.read(
        Buffer.alloc(1),
        0,
        1,
        count,
      );
      if (extra > 0)
        throw new ArtifactReaderFailure(
          "integrity",
          `Artifact changed during read: ${path}`,
        );
      const after = await file.stat({ bigint: true });
      const current = await afterValidation(path, "during read", () =>
        fileSystem.lstat(path),
      );
      if (
        [after, current].some(
          (stat) =>
            !stat.isFile() ||
            stat.dev !== initial.dev ||
            stat.ino !== initial.ino ||
            stat.size !== initial.size ||
            stat.mtimeNs !== initial.mtimeNs ||
            stat.ctimeNs !== initial.ctimeNs,
        ) ||
        BigInt(count) !== initial.size
      )
        throw new ArtifactReaderFailure(
          "integrity",
          `Artifact changed during read: ${path}`,
        );
      assertArtifactReadActive(signal);
      const bytes = content;
      return {
        bytes,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
    },
  );
};
