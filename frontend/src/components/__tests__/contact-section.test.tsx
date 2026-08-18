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

/** Reveal the optional technical fields, which are collapsed by default. */
async function openTechnical(user: User) {
  await user.click(screen.getByRole("button", { name: /Add technical detail/ }));
}

/**
 * Fill the four fields the default view asks for. This is the common path: a
 * reader who fills only these can send a complete, valid enquiry.
 */
async function fillRequired(user: User) {
  await user.type(screen.getByLabelText("Name"), "Jane Doe");
  await user.type(screen.getByLabelText("Work email"), "jane@example.com");
  await user.type(screen.getByLabelText("Company"), "Acme");
  await user.type(screen.getByLabelText("Message"), "Hello!");
}

/**
 * Fill everything, including the qualification detail behind the disclosure.
 * The form is payments-shaped: it asks what the agent can pay for and which
 * policy must be enforced, because those are the two answers that make a pilot
 * conversation possible at all — but it asks them one level deeper, so the
 * default view is an enquiry form rather than a questionnaire.
 */
async function fillForm(user: User) {
  await fillRequired(user);
  await openTechnical(user);
  await user.type(
    screen.getByLabelText("What can the agent purchase or pay?"),
    "Supplier invoices",
  );
  await user.type(
    screen.getByLabelText("Which policy must be enforced?"),
    "Per-action limit of $1,000",
  );
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

    it("shows only the four common-path fields by default", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeInTheDocument();
      expect(screen.getByLabelText("Work email")).toBeInTheDocument();
      expect(screen.getByLabelText("Company")).toBeInTheDocument();
      expect(screen.getByLabelText("Message")).toBeInTheDocument();

      // Qualification detail is one level deeper, not on the default view.
      expect(screen.queryByLabelText("Payment rail or provider")).not.toBeInTheDocument();
      expect(screen.queryByLabelText("Agent framework")).not.toBeInTheDocument();
      expect(
        screen.queryByLabelText("What can the agent purchase or pay?"),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByLabelText("Which policy must be enforced?"),
      ).not.toBeInTheDocument();
    });

    it("reveals the technical fields when the disclosure is opened", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);
      await openTechnical(user);

      expect(screen.getByLabelText("Payment rail or provider")).toBeInTheDocument();
      expect(screen.getByLabelText("Agent framework")).toBeInTheDocument();
      expect(
        screen.getByLabelText("What can the agent purchase or pay?"),
      ).toBeInTheDocument();
      expect(screen.getByLabelText("Which policy must be enforced?")).toBeInTheDocument();
    });

    it("renders the submit button", () => {
      render(<ContactSection />);
      expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    });

    it("renders the sidebar with the contact address and the response commitment", () => {
      render(<ContactSection />);
      expect(screen.getAllByText("sales@inntris.com").length).toBeGreaterThan(0);
      expect(screen.getByText("Within one business day")).toBeInTheDocument();
    });

    /* There is no security@inntris.com mailbox. The evidence-pack verifier's
       README tells auditors to write in on a key discrepancy, so the address
       the site publishes has to be one that actually resolves — a
       dedicated-looking security@ that bounces is worse than a shared box
       that answers. */
    it("does not publish an address that has no mailbox behind it", () => {
      const { container } = render(<ContactSection />);
      expect(container.textContent ?? "").not.toContain("security@inntris.com");
      expect(container.innerHTML).not.toContain("mailto:security@inntris.com");
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

    it("marks the four common-path inputs required and the deeper ones optional", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeRequired();
      expect(screen.getByLabelText("Work email")).toBeRequired();
      expect(screen.getByLabelText("Company")).toBeRequired();
      expect(screen.getByLabelText("Message")).toBeRequired();

      await openTechnical(user);
      expect(
        screen.getByLabelText("What can the agent purchase or pay?"),
      ).not.toBeRequired();
      expect(screen.getByLabelText("Which policy must be enforced?")).not.toBeRequired();
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

  describe("inline validation", () => {
    it("reports a malformed email on blur, before submit", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Work email"), "not-an-address");
      await user.tab();

      expect(
        await screen.findByText("That does not look like an email address."),
      ).toBeInTheDocument();
      expect(screen.getByLabelText("Work email")).toHaveAttribute("aria-invalid", "true");
      // Nothing was sent: the reader has not pressed anything yet.
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("clears the error once the address is corrected", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);

      const email = screen.getByLabelText("Work email");
      await user.type(email, "nope");
      await user.tab();
      expect(
        await screen.findByText("That does not look like an email address."),
      ).toBeInTheDocument();

      await user.type(email, "@example.com");
      await waitFor(() => {
        expect(
          screen.queryByText("That does not look like an email address."),
        ).not.toBeInTheDocument();
      });
    });

    it("blocks submission and flags empty required fields", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.click(screen.getByRole("button", { name: "Send message" }));

      expect(mockFetch).not.toHaveBeenCalled();
      expect(await screen.findByText("Tell us who you are.")).toBeInTheDocument();
      expect(screen.getByText("We need an address to reply to.")).toBeInTheDocument();
    });

    it("sends when only the four common-path fields are filled", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await fillRequired(user);
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Message received")).toBeInTheDocument();
      });
      // The optional fields still travel, empty, exactly as before.
      expect(mockFetch).toHaveBeenCalledWith(
        "https://formspree.io/f/mpqjkbre",
        expect.objectContaining({
          body: JSON.stringify({
            name: "Jane Doe",
            email: "jane@example.com",
            company: "Acme",
            rail: "",
            framework: "",
            purchases: "",
            policy: "",
            message: "Hello!",
          }),
        }),
      );
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

    it("all form inputs have associated labels via htmlFor/id", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);
      await openTechnical(user);

      const labels = [
        "Name",
        "Work email",
        "Company",
        "Message",
        "Payment rail or provider",
        "Agent framework",
        "What can the agent purchase or pay?",
        "Which policy must be enforced?",
      ];
      labels.forEach((label) => {
        const input = screen.getByLabelText(label);
        expect(input).toBeInTheDocument();
        expect(input.id).toBeTruthy();
      });
    });

    it("the disclosure toggle reports its own expanded state", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);
      const toggle = screen.getByRole("button", { name: /Add technical detail/ });
      expect(toggle).toHaveAttribute("aria-expanded", "false");
      await user.click(toggle);
      expect(toggle).toHaveAttribute("aria-expanded", "true");
    });
  });
});
