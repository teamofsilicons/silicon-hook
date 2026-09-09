import { render } from "solid-js/web";
import { ErrorBoundary } from "solid-js";
import App from "./App";
import "./styles.css";
render(
  () => (
    <ErrorBoundary
      fallback={(error) => (
        <main class="boot">
          <h1>Unable to load Hook</h1>
          <p>{String(error.message || error)}</p>
          <button onClick={() => location.reload()}>Reload</button>
        </main>
      )}
    >
      <App />
    </ErrorBoundary>
  ),
  document.getElementById("root")!,
);
