import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ContactSection from "../contact-section";

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

describe("ContactSection", () => {
  describe("rendering", () => {
    it("renders the section heading and subtitle", () => {
      render(<ContactSection />);
      expect(screen.getByText("Get in touch")).toBeInTheDocument();
      expect(screen.getByText("Talk to us about your agents.")).toBeInTheDocument();
    });

    it("renders all form fields with correct labels", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeInTheDocument();
      expect(screen.getByLabelText("Email")).toBeInTheDocument();
      expect(screen.getByLabelText("Subject")).toBeInTheDocument();
      expect(screen.getByLabelText("Message")).toBeInTheDocument();
    });

    it("renders the submit button", () => {
      render(<ContactSection />);
      expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    });

    it("renders the sidebar with contact info", () => {
      render(<ContactSection />);
      expect(screen.getByText("applications@inntris.com")).toBeInTheDocument();
      expect(screen.getByText("Within 24 hours")).toBeInTheDocument();
    });

    it("renders the section with id='contact' for anchor navigation", () => {
      const { container } = render(<ContactSection />);
      expect(container.querySelector("section#contact")).toBeInTheDocument();
    });

    it("renders the email link with correct href", () => {
      render(<ContactSection />);
      const emailLink = screen.getByText("applications@inntris.com");
      expect(emailLink).toHaveAttribute("href", "mailto:applications@inntris.com");
    });
  });

  describe("form interaction", () => {
    it("updates input values when user types", async () => {
      const user = userEvent.setup();
      render(<ContactSection />);

      const nameInput = screen.getByLabelText("Name");
      const emailInput = screen.getByLabelText("Email");
      const subjectInput = screen.getByLabelText("Subject");
      const messageInput = screen.getByLabelText("Message");

      await user.type(nameInput, "Jane Doe");
      await user.type(emailInput, "jane@example.com");
      await user.type(subjectInput, "Partner inquiry");
      await user.type(messageInput, "Hello, I'd like to learn more.");

      expect(nameInput).toHaveValue("Jane Doe");
      expect(emailInput).toHaveValue("jane@example.com");
      expect(subjectInput).toHaveValue("Partner inquiry");
      expect(messageInput).toHaveValue("Hello, I'd like to learn more.");
    });

    it("has required attributes on all inputs", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Name")).toBeRequired();
      expect(screen.getByLabelText("Email")).toBeRequired();
      expect(screen.getByLabelText("Subject")).toBeRequired();
      expect(screen.getByLabelText("Message")).toBeRequired();
    });

    it("email input has type='email'", () => {
      render(<ContactSection />);
      expect(screen.getByLabelText("Email")).toHaveAttribute("type", "email");
    });
  });

  describe("form submission — success", () => {
    it("submits form data to Formspree and shows success message", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Message received")).toBeInTheDocument();
      });

      // Verify fetch was called with correct data
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
            subject: "Inquiry",
            message: "Hello!",
          }),
        })
      );
    });

    it("shows 'Send another message' button after success", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Send another message")).toBeInTheDocument();
      });
    });

    it("returns to form when 'Send another message' is clicked", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(screen.getByText("Send another message")).toBeInTheDocument();
      });

      await user.click(screen.getByText("Send another message"));

      // Form should be visible again with empty fields
      expect(screen.getByLabelText("Name")).toHaveValue("");
      expect(screen.getByLabelText("Email")).toHaveValue("");
      expect(screen.getByRole("button", { name: "Send message" })).toBeInTheDocument();
    });
  });

  describe("form submission — error", () => {
    it("shows error message when API returns non-ok response", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at applications@inntris.com")
        ).toBeInTheDocument();
      });
    });

    it("shows error message when fetch throws a network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at applications@inntris.com")
        ).toBeInTheDocument();
      });
    });

    it("keeps form data intact after error so user can retry", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        expect(
          screen.getByText("Something went wrong. Email us directly at applications@inntris.com")
        ).toBeInTheDocument();
      });

      // Form values should still be filled
      expect(screen.getByLabelText("Name")).toHaveValue("Jane Doe");
      expect(screen.getByLabelText("Email")).toHaveValue("jane@example.com");
      expect(screen.getByLabelText("Subject")).toHaveValue("Inquiry");
      expect(screen.getByLabelText("Message")).toHaveValue("Hello!");
    });
  });

  describe("submit button state", () => {
    it("shows 'Sending...' and is disabled while submitting", async () => {
      // Keep the fetch pending
      let resolveFetch: (value: { ok: boolean }) => void;
      mockFetch.mockImplementationOnce(
        () => new Promise((resolve) => { resolveFetch = resolve; })
      );

      const user = userEvent.setup();
      render(<ContactSection />);

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      // Button should be in submitting state
      const button = screen.getByRole("button", { name: "Sending..." });
      expect(button).toBeDisabled();

      // Resolve the fetch to clean up
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

      await user.type(screen.getByLabelText("Name"), "Jane Doe");
      await user.type(screen.getByLabelText("Email"), "jane@example.com");
      await user.type(screen.getByLabelText("Subject"), "Inquiry");
      await user.type(screen.getByLabelText("Message"), "Hello!");
      await user.click(screen.getByRole("button", { name: "Send message" }));

      await waitFor(() => {
        const successContainer = screen.getByText("Message received").closest("[aria-live]");
        expect(successContainer).toHaveAttribute("aria-live", "polite");
      });
    });

    it("all form inputs have associated labels via htmlFor/id", () => {
      render(<ContactSection />);
      const labels = ["Name", "Email", "Subject", "Message"];
      labels.forEach((label) => {
        const input = screen.getByLabelText(label);
        expect(input).toBeInTheDocument();
        expect(input.id).toBeTruthy();
      });
    });
  });
});
