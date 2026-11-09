import { useEffect, useState } from "react";

/** Hash route: "#/scans/<id>?tab=findings" -> ["scans", "<id>"]. */
export function parseRoute(hash: string): string[] {
  const path = hash.split("?")[0];
  return path.replace(/^#\/?/, "").split("/").filter(Boolean);
}

export function navigate(to: string) {
  if (!to.startsWith("#")) to = "#" + (to.startsWith("/") ? to : "/" + to);
  if (window.location.hash === to) {
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    return;
  }
  window.location.hash = to;
}

export function useRoute(): string[] {
  const [segments, setSegments] = useState<string[]>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = () => setSegments(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return segments;
}
