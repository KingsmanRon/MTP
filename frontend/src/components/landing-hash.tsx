"use client";

import { useEffect } from "react";

/**
 * On a bare landing (no hash in the URL), reflect the #overview anchor so
 * visitors arrive at /#overview. Uses replaceState, so there is no reload,
 * no extra history entry, and no scroll jump (overview is the top section).
 * An explicit deep link like /#modules is left untouched.
 */
export function LandingHash() {
  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", "#overview");
    }
  }, []);

  return null;
}
