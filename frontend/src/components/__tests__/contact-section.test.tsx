import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ContactSection from "../contact-section";

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

type User = ReturnType<typeof userEvent.setup>;

/**
 * Fill every required text input. The form is payments-shaped: it asks what
 * the agent can pay for and which policy must be enforced, because those are
 * the two answers that make a pilot conversation possible at all.
 */
async function fillForm(user: User) {
  await user.type(screen.getByLabelText("Name"), "Jane Doe");
  await user.type(screen.getByLabelText("Work email"), "jane@example.com");
  await user.type(screen.getByLabelText("Company"), "Acme");
  await user.type(
    screen.getByLabelText("What can the agent purchase or pay?"),
    "Supplier invoices",
  );
  await user.type(
    screen.getByLabelText("Which policy must be enforced?"),
    "Per-action limit of $1,000",
  );
  await user.type(screen.getByLabelText("Message"), "Hello!");
}

describe("ContactSection", () => {
  describe("rendering", () => {
    it("renders the section heading and intro", () => {
      render(<ContactSection />);
      expect(screen.getByText("Get in touch")).toBeInTheDocument();
      expect(
        screen.getByText("Talk to us about an agent payment workflow."),
      ).toBeInTheDocument();
    });

    it("renders all form fields with correct labels", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeInTheDocument();
      expect(screen.getByLabelText("Work email")).toBeInTheDocument();
      expect(screen.getByLabelText("Company")).toBeInTheDocument();
      expect(screen.getByLabelText("Payment rail or provider")).toBeInTheDocument();
      expect(screen.getByLabelText("Agent framework")).toBeInTheDocument();
      expect(
        screen.getByLabelText("What can the agent purchase or pay?"),
      ).toBeInTheDocument();
      expect(screen.getByLabelText("Which policy must be enforced?")).toBeInTheDocument();
      expect(screen.getByLabelText("Message")).toBeInTheDocument();
    });

    it("renders the submit button", () => {
      render(<ContactSection />);
      expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    });

    it("renders the sidebar with both contact addresses and the response commitment", () => {
      render(<ContactSection />);
      expect(screen.getAllByText("sales@inntris.com").length).toBeGreaterThan(0);
      expect(screen.getAllByText("security@inntris.com").length).toBeGreaterThan(0);
      expect(screen.getByText("Within one business day")).toBeInTheDocument();
    });

    /* The evidence-pack verifier's README tells auditors to write to this
       address on any key discrepancy. If the site drops it, that instruction
       dead-ends at the moment someone is deciding whether to trust the keys. */
    it("links the security address as a mailto", () => {
      render(<ContactSection />);
      const links = screen.getAllByText("security@inntris.com");
      expect(links[0]).toHaveAttribute("href", "mailto:security@inntris.com");
    });

    it("renders the section with id='contact' for anchor navigation", () => {
      const { container } = render(<ContactSection />);
      expect(container.querySelector("section#contact")).toBeInTheDocument();
    });

    it("renders the sales email link with correct href", () => {
      render(<ContactSection />);
      const emailLinks = screen.getAllByText("sales@inntris.com");
      expect(emailLinks.length).toBeGreaterThan(0);
      expect(emailLinks[0]).toHaveAttribute("href", "mailto:sales@inntris.com");
    });

    it("does not present applications@inntris.com as the buyer-facing address", () => {
      const { container } = render(<ContactSection />);
      expect(container.textContent ?? "").not.toContain("applications@inntris.com");
    });

    /* v1 said enquiries were "reviewed directly by the founder" — true, but it
       volunteers the solo-founder fact to exactly the audience the risk slide
       exists to reassure. The replacement is a response commitment. */
    it("does not disclose the org chart in place of a response commitment", () => {
      const { container } = render(<ContactSection />);
      expect(container.textContent ?? "").not.toContain("founder");
    });
  });

  describe("form interaction", () => {
    it("updates input values when user types", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);

      expect(screen.getByLabelText("Name")).toHaveValue("Jane Doe");
      expect(screen.getByLabelText("Work email")).toHaveValue("jane@example.com");
      expect(screen.getByLabelText("Company")).toHaveValue("Acme");
      expect(screen.getByLabelText("What can the agent purchase or pay?")).toHaveValue(
        "Supplier invoices",
      );
      expect(screen.getByLabelText("Which policy must be enforced?")).toHaveValue(
        "Per-action limit of $1,000",
      );
      expect(screen.getByLabelText("Message")).toHaveValue("Hello!");
    });

    it("has required attributes on all text inputs", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeRequired();
      expect(screen.getByLabelText("Work email")).toBeRequired();
      expect(screen.getByLabelText("Company")).toBeRequired();
      expect(screen.getByLabelText("What can the agent purchase or pay?")).toBeRequired();
      expect(screen.getByLabelText("Which policy must be enforced?")).toBeRequired();
      expect(screen.getByLabelText("Message")).toBeRequired();
    });

    it("email input has type='email'", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Work email")).toHaveAttribute("type", "email");
    });
  });

  describe("form submission — success", () => {
    it("submits form data to Formspree and shows success message", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Message received")).toBeInTheDocument();
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://formspree.io/f/mpqjkbre",
        expect.objectContaining({
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            name: "Jane Doe",
            email: "jane@example.com",
            company: "Acme",
            rail: "",
            framework: "",
            purchases: "Supplier invoices",
            policy: "Per-action limit of $1,000",
            message: "Hello!",
          }),
        }),
      );
    });

    it("shows 'Send another message' button after success", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Send another message")).toBeInTheDocument();
      });
    });

    it("returns to form when 'Send another message' is clicked", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Send another message")).toBeInTheDocument();
      });

      await user.click(screen.getByText("Send another message"));

      expect(screen.getByLabelText("Name")).toHaveValue("");
      expect(screen.getByLabelText("Work email")).toHaveValue("");
      expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    });
  });

  describe("form submission — error", () => {
    it("shows error message when API returns non-ok response", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at sales@inntris.com"),
        ).toBeInTheDocument();
      });
    });

    it("shows error message when fetch throws a network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at sales@inntris.com"),
        ).toBeInTheDocument();
      });
    });

    it("keeps form data intact after error so user can retry", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at sales@inntris.com"),
        ).toBeInTheDocument();
      });

      expect(screen.getByLabelText("Name")).toHaveValue("Jane Doe");
      expect(screen.getByLabelText("Work email")).toHaveValue("jane@example.com");
      expect(screen.getByLabelText("Company")).toHaveValue("Acme");
      expect(screen.getByLabelText("Message")).toHaveValue("Hello!");
    });
  });

  describe("submit button state", () => {
    it("shows 'Sending...' and is disabled while submitting", async () => {
      let resolveFetch: (value: { ok: boolean }) => void;
      mockFetch.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFetch = resolve;
          }),
      );

      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      const button = screen.getByRole("button", { name: "Sending..." });
      expect(button).toBeDisabled();

      resolveFetch!({ ok: true });
      await waitFor(() => {
        expect(screen.getByText("Message received")).toBeInTheDocument();
      });
    });
  });

  describe("accessibility", () => {
    it("success message container has aria-live='polite'", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillForm(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        const successContainer = screen.getByText("Message received").closest("[aria-live]");
        expect(successContainer).toHaveAttribute("aria-live", "polite");
      });
    });

    it("all form inputs have associated labels via htmlFor/id", () => {
      render(<ContactSection />);
      const labels = [
        "Name",
        "Work email",
        "Company",
        "What can the agent purchase or pay?",
        "Which policy must be enforced?",
        "Message",
      ];
      labels.forEach((label) => {
        const input = screen.getByLabelText(label);
        expect(input).toBeInTheDocument();
        expect(input.id).toBeTruthy();
      });
    });
  });
});
