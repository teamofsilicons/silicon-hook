/** notFound() inside the workspace (an item that does not exist, or is not shared with you): said inside the shell. */
import { SearchX } from "lucide-react";
import { Problem } from "@/components/foundation/feedback/problem";
import { ButtonLink } from "@/components/foundation/button-link";
import { appConfig } from "@/lib/app.config";

export default function WorkspaceNotFound() {
  return (
    <Problem
      layout="inset"
      icon={<SearchX strokeWidth={1.5} />}
      title="This is not here"
      actions={<ButtonLink href={appConfig.home}>Back to {appConfig.nav[0]?.label ?? appConfig.name}</ButtonLink>}
    >
      <p>It may have been deleted, or it was never shared with your account. If someone shared it with you, ask them to check the c: or si: id they used.</p>
    </Problem>
  );
}
