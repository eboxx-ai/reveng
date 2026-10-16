import {
  lstat,
  mkdtemp,
  open,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ArtifactReaderFailure } from "./ArtifactReader.js";
import { peekArtifactMagic } from "./readStableArtifact.js";

describe("peekArtifactMagic", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "rea-peek-"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns the leading bytes without admitting the whole file under a budget", async () => {
    // A file far larger than the few bytes requested is still classifiable: the
    // peek reads only the prefix and never buffers the remainder.
    const path = join(dir, "big.bin");
    const body = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      Buffer.alloc(1_000_000, 0x7a),
    ]);
    await writeFile(path, body);
    const magic = await peekArtifactMagic(path, 4);
    expect([...magic]).toEqual([0x50, 0x4b, 0x03, 0x04]);
  });

  it("returns fewer bytes when the file is shorter than requested", async () => {
    const path = join(dir, "short.bin");
    await writeFile(path, Buffer.from([0xca, 0xfe]));
    const magic = await peekArtifactMagic(path, 4);
    expect([...magic]).toEqual([0xca, 0xfe]);
  });

  it("refuses a file replaced between validation and open", async () => {
    const path = join(dir, "swapped.bin");
    const replacement = join(dir, "replacement.bin");
    await writeFile(path, Buffer.from([0xca, 0xfe, 0xba, 0xbe]));
    await writeFile(replacement, Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    const swapping = {
      lstat: (p: string) => lstat(p, { bigint: true }),
      open: async (p: string, flags: number) => {
        await rename(replacement, p);
        return open(p, flags);
      },
    };
    await expect(
      peekArtifactMagic(path, 4, undefined, swapping),
    ).rejects.toMatchObject({ reason: "integrity" });
  });

  it("refuses a symlink rather than following it", async () => {
    const target = join(dir, "target.bin");
    const link = join(dir, "link.bin");
    await writeFile(target, Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    await symlink(target, link);
    await expect(peekArtifactMagic(link, 4)).rejects.toBeInstanceOf(
      ArtifactReaderFailure,
    );
  });
});
