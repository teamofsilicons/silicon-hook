/** The browser icon: the app's logo on a rounded cream tile (lib/brand-svg.ts) as a 512 px PNG, generated at build time. */
import { ImageResponse } from "next/og";
import { markSvg, svgDataUri } from "@/lib/brand-svg";

export const size = { width: 512, height: 512 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    <img src={svgDataUri(markSvg({ rounded: true }))} width={512} height={512} alt="" />,
    size,
  );
}
