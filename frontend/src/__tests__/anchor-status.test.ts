import { getAdminAnchorDisplayState } from "@/lib/admin/anchor-status";

describe("getAdminAnchorDisplayState", () => {
  it("shows Awaiting batch before a Merkle batch is assigned", () => {
    expect(
      getAdminAnchorDisplayState({
        merkle_root_id: null,
        transaction_hash: null,
        block_number: null,
      })
    ).toBe("awaiting_batch");
  });

  it("shows Pending after batching but before transaction submission", () => {
    expect(
      getAdminAnchorDisplayState({
        merkle_root_id: "batch-id",
        transaction_hash: null,
        block_number: null,
      })
    ).toBe("pending");
  });

  it("shows Submitted when a tx hash exists without a confirmed block", () => {
    expect(
      getAdminAnchorDisplayState({
        merkle_root_id: "batch-id",
        transaction_hash: "0xabc",
        block_number: null,
      })
    ).toBe("submitted");
  });

  it("shows Anchored only when tx hash and block number both exist", () => {
    expect(
      getAdminAnchorDisplayState({
        merkle_root_id: "batch-id",
        transaction_hash: "0xabc",
        block_number: 50536889,
      })
    ).toBe("anchored");
  });
});
