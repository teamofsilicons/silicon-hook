"use client";

/**
 * The signed-in account's menu behind its photo (Arc's user menu): the profile photo from Silicon Accounts (`pfp_url`),
 * the display name, the c: or si: id and whether it is a Carbon or a Silicon, the account's own page at Silicon Accounts, search, and sign out. Below 640 px it opens as a bottom sheet.
 */
import { CircleUserRound, Search } from "lucide-react";
import { UserMenu } from "@/components/silicon-ui/user-menu/user-menu";
import type { SessionAccount } from "@/lib/account";
import { kindNoun } from "@/lib/format";
import { notifyError } from "@/lib/notify";
import { openCommandPalette } from "@/lib/commands";
import { useSignOut } from "@/lib/client/session";

export function AccountMenu({ account, accountsUrl, isApple }: { account: SessionAccount; accountsUrl: string; isApple: boolean }) {
  const { signOut } = useSignOut();
  return (
    <UserMenu
      user={{ name: account.display_name, email: account.id, plan: kindNoun(account.kind), avatarSrc: account.pfp_url ?? undefined }}
      showTheme={false}
      onSignOut={async () => {
        try {
          await signOut();
        } catch (failure) {
          notifyError(failure, "Could not sign out");
        }
      }}
      align="end"
      items={[
        { label: "Your account", icon: <CircleUserRound size={16} strokeWidth={1.75} />, onSelect: () => void window.open(accountsUrl, "_blank", "noopener") },
        { label: "Search and jump", icon: <Search size={16} strokeWidth={1.75} />, keys: isApple ? ["⌘", "K"] : ["Ctrl", "K"], onSelect: openCommandPalette },
      ]}
    />
  );
}
