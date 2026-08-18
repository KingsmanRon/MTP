/**
 * Single source of truth for brand identity and navigation labels.
 *
 * Before this module the site carried two product names and two taglines —
 * "Inntris / Independent authorisation and verifiable evidence for agent
 * actions. Payments first." on the marketing pages, "Inntris Core /
 * Cryptographic verification for AI agents" on every product surface. A
 * visitor crossing from the homepage to a receipt was told they had arrived
 * somewhere else. "Inntris Core" is not a shipped product tier and is not
 * introduced anywhere on the marketing site, so it is gone rather than
 * explained.
 *
 * Nav and CTA labels live here for the same reason: one destination must not
 * be reachable under several different names, and the same name must not
 * resolve to two destinations.
 */

export const BRAND_NAME = "Inntris";
export const BRAND_TAGLINE =
  "Independent authorisation and verifiable evidence for agent actions. Payments first.";
export const BRAND_COPYRIGHT = "© 2026 Inntris, Inc.";
export const CONTACT_EMAIL = "sales@inntris.com";

/**
 * The public verifier. A reader inspecting a receipt is testing the
 * independence claim, so the next step offered to them is the tool that lets
 * them check it without this site in the loop.
 */
export const VERIFIER_REPO_URL = "https://github.com/Inntris/inntris-verify";

/** The one string every `/pilot` call to action renders. */
export const PILOT_HREF = "/pilot";
export const PILOT_CTA_LABEL = "Scope a 14-day pilot";

/**
 * Labels whose destination is ambiguous unless they are named apart. The
 * homepage section explaining how verification works and the tool that
 * verifies a receipt were both called "Verify".
 */
export const VERIFY_SECTION_LABEL = "How verification works";
export const VERIFY_SECTION_HREF = "/#verify";
export const VERIFY_TOOL_LABEL = "Verify a receipt";
export const VERIFY_TOOL_HREF = "/verify";

export interface NavLink {
  href: string;
  label: string;
}

/**
 * Primary homepage navigation.
 *
 * The homepage renders thirteen sections; five are reachable from here. The
 * omissions are deliberate, and are recorded so the next edit does not have to
 * guess:
 *
 *   #overview      — the hero. It is where the reader already is.
 *   #problem       — narrative lead-in to #payments; reaching it directly
 *                    strands the reader before the answer.
 *   #why-now       — market framing. Argument, not a destination a returning
 *                    reader navigates to.
 *   #live-proof    — reached from the hero CTA and from #verify, which is
 *                    where a reader looking for evidence actually goes.
 *   #independence  — supports #verify; it is read on the way past, not sought.
 *   #platform      — the four product surfaces each carry their own link.
 *   #boundaries    — linked from #payments and from /security.
 *   #pilot         — represented by the header CTA, so it is not repeated as
 *                    a nav item. Two adjacent links to /pilot is the defect
 *                    this list exists to avoid.
 *   #contact       — footer.
 *
 * Every href below must resolve to a section id that exists on the homepage.
 */
export const PRIMARY_NAV: NavLink[] = [
  { href: "/#payments", label: "Payments" },
  { href: "/#protocols", label: "Protocols" },
  { href: VERIFY_SECTION_HREF, label: VERIFY_SECTION_LABEL },
  { href: "/#use-cases", label: "Use cases" },
  { href: "/docs", label: "Docs" },
];

/** Footer navigation. Shared by every page through `SiteFooter`. */
export const FOOTER_NAV: NavLink[] = [
  { href: "/#payments", label: "Payments" },
  { href: "/#use-cases", label: "Use cases" },
  { href: VERIFY_TOOL_HREF, label: VERIFY_TOOL_LABEL },
  { href: "/docs", label: "Docs" },
  { href: "/security", label: "Security" },
  { href: "/#contact", label: "Contact" },
];
