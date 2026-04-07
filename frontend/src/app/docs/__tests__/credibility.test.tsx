import { render } from "@testing-library/react";
import DocsPage from "../page";

describe("Docs page credibility regression", () => {
  it("does not contain the 'VISA network' speculative line", () => {
    const { container } = render(<DocsPage />);
    expect(container.textContent ?? "").not.toContain("VISA network");
  });

  it("does not contain the prior speculative on-premise line", () => {
    const { container } = render(<DocsPage />);
    expect(container.textContent ?? "").not.toContain(
      "Optional on-premise deployment available for compliance-heavy industries.",
    );
  });

  it("contains the new operational verification-layer copy", () => {
    const { container } = render(<DocsPage />);
    expect(container.textContent ?? "").toContain(
      "Inntris provides a verification layer for teams that need signed decisions",
    );
  });

  it("contains the new operational deployment review copy", () => {
    const { container } = render(<DocsPage />);
    expect(container.textContent ?? "").toContain(
      "Deployment and security requirements are reviewed with each team during evaluation.",
    );
  });
});
