import { createResource } from "solid-js";
export function load<T>(source: () => unknown, fetcher: () => Promise<T>) {
  const [state, actions] = createResource(source, async () => {
    try {
      return { value: await fetcher(), error: undefined };
    } catch (error) {
      return { value: undefined, error };
    }
  });
  return {
    data: () => state()?.value,
    error: () => state()?.error,
    loading: () => state.loading,
    refresh: () => actions.refetch(),
  };
}
