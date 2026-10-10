/** The home-screen icon: the glyph on a full square of the app's colour (the system rounds the corners itself). */
import { ImageResponse } from "next/og";
import { markSvg, svgDataUri } from "@/lib/brand-svg";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    <img src={svgDataUri(markSvg({ shape: "square", glyph: 0.52 }))} width={180} height={180} alt="" />,
    size,
  );
}
