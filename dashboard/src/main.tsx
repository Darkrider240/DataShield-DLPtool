import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './hooks/useAuth';
import Navbar from './components/Navbar';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Employees from './pages/Employees';
import Events from './pages/Events';
import Policies from './pages/Policies';
import Alerts from './pages/Alerts';
import Encryption from './pages/Encryption';
import Reports from './pages/Reports';
import './index.css';

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 10_000 } } });

function ProtectedLayout() {
  const { user, loading } = useAuth();
  if (loading) return <div className="splash">Loading DataShield…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return (
    <div className="app-shell">
      <Navbar />
      <main className="main-content">
        <Routes>
          <Route path="/"           element={<Dashboard />} />
          <Route path="/employees"  element={<Employees />} />
          <Route path="/events"     element={<Events />} />
          <Route path="/policies"   element={<Policies />} />
          <Route path="/alerts"     element={<Alerts />} />
          <Route path="/encryption" element={<Encryption />} />
          <Route path="/reports"    element={<Reports />} />
          <Route path="*"           element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/*"    element={<ProtectedLayout />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
