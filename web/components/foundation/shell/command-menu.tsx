"use client";

/**
 * The ⌘K command palette: Arc's command-palette block in a modal layer. Commands come from the registry
 * (lib/commands.ts): the shell's navigation, theme and account commands plus whatever the current page adds.
 */
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { CommandPalette, type CommandItem } from "@/components/arc/command-palette/command-palette";
import { returnFocusTo, useLayerOpener } from "@/components/arc/lib/return-focus";
import { closeCommandPalette, setCommandPaletteOpen, useCommandPaletteOpen, useCommands } from "@/lib/commands";
import styles from "./shell.module.css";

export function CommandMenu() {
  const open = useCommandPaletteOpen();
  // Opened by ⌘K or the search button (no Radix Trigger): closing returns focus to what had it (lib/return-focus.ts).
  const opener = useLayerOpener(open);
  const commands = useCommands();
  const items: CommandItem[] = commands.map(({ id, label, description, group, keywords, icon, shortcut }) => ({ id, label, description, group, keywords, icon, shortcut }));
  const run = (item: CommandItem) => {
    closeCommandPalette();
    const command = commands.find(entry => entry.id === item.id);
    // Run after the dialog has started closing, so focus returns before the command moves it (navigation, a drawer).
    if (command) requestAnimationFrame(() => command.run());
  };
  return (
    <DialogPrimitive.Root open={open} onOpenChange={setCommandPaletteOpen}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className={styles.paletteOverlay} />
        <div className={styles.palettePositioner}>
          <DialogPrimitive.Content className={styles.palettePanel} aria-describedby={undefined} onCloseAutoFocus={returnFocusTo(opener)}>
            <DialogPrimitive.Title className="sr-only">Search and jump</DialogPrimitive.Title>
            {open ? (
              <CommandPalette items={items} placeholder="Search pages and actions" label="Search pages and actions" autoFocus onClose={closeCommandPalette} onSelect={run} />
            ) : null}
          </DialogPrimitive.Content>
        </div>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
