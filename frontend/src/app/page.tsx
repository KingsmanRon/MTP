import { LandingHash } from "@/components/landing-hash";
import { SiteNav } from "@/components/landing/site-nav";
import { Hero, StatStrip } from "@/components/landing/hero";
import {
  Integration,
  PolicyEnforcement,
  Problem,
  Solution,
  VerificationStream,
} from "@/components/landing/sections-a";
import {
  DesignPartners,
  FinalCta,
  Modules,
  ProductPayloads,
  SiteFooter,
  Specs,
  StatementBlock,
  TrustStack,
} from "@/components/landing/sections-b";

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Inntris",
  legalName: "Inntris Inc.",
  url: "https://www.inntris.com",
  logo: "https://www.inntris.com/logo.svg",
  description:
    "Pre-execution policy enforcement and verifiable evidence for high-risk AI agent actions.",
  foundingDate: "2025",
};

export default function LandingPage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <LandingHash />
      <div className="theme-light min-h-screen bg-background text-foreground">
        <SiteNav />
        <main>
          <Hero />
          <StatStrip />
          <Problem />
          <Solution />
          <Integration />
          <VerificationStream />
          <ProductPayloads />
          <PolicyEnforcement />
          <Modules />
          <TrustStack />
          <StatementBlock />
          <Specs />
          <DesignPartners />
          <FinalCta />
        </main>
        <SiteFooter />
      </div>
    </>
  );
}
