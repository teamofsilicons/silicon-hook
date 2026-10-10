/** While a workspace page loads: its header and regions in their final positions (Arc: skeletons, never a spinner). */
import { PageSkeleton } from "@/components/foundation/feedback/page-skeleton";

export default function Loading() {
  return <PageSkeleton />;
}
