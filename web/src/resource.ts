import { createResource } from "solid-js";
export function load<T>(source: () => unknown, fetcher: () => Promise<T>) {
  type Result = { value: Awaited<T> | undefined; error: unknown };
  let revision = 0;
  let latest: Result | undefined;
  const [state, actions] = createResource(source, async () => {
    const requestRevision = ++revision;
    let result: Result;
    try {
      result = { value: await fetcher(), error: undefined };
    } catch (error) {
      result = { value: undefined, error };
    }
    // A verified login can replace the resource while an older session read
    // is pending. Its late response must not restore the previous account.
    if (requestRevision !== revision) return latest;
    latest = result;
    return result;
  });
  return {
    data: () => state()?.value,
    error: () => state()?.error,
    loading: () => state.loading,
    refresh: () => actions.refetch(),
    set: (value: Awaited<T>) => {
      revision++;
      latest = { value, error: undefined };
      actions.mutate(latest);
    },
  };
}
