import { redirect } from "next/navigation";

/**
 * Historical admin sign-in URL.
 *
 * The console has a single sign-in page at /login — that is where the
 * authenticated layout sends unauthenticated visitors, and where the marketing
 * pages point. This route stays only so existing links and bookmarks resolve
 * instead of 404ing, and so there is exactly one login screen to maintain.
 */
export default function AdminLoginRedirect() {
  redirect("/login");
}
