import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './styles.css';

type ErrorBoundaryProps = {
  children: React.ReactNode;
};

type ErrorBoundaryState = {
  error: Error | null;
};

class HubErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('Morph Hub UI crashed', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <main className="runtime-failure" role="alert">
        <section className="runtime-failure-panel">
          <div className="brand-mark">M</div>
          <div>
            <p className="runtime-failure-kicker">Morph Hub operator console</p>
            <h1>Console rendering failed</h1>
            <p>
              The browser UI stopped before it could render the current Hub
              state. The API state file was not changed by this screen.
            </p>
            <pre>{this.state.error.message}</pre>
            <button type="button" onClick={() => window.location.reload()}>
              Reload console
            </button>
          </div>
        </section>
      </main>
    );
  }
}

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Morph Hub root element not found.');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <HubErrorBoundary>
      <App />
    </HubErrorBoundary>
  </React.StrictMode>
);
