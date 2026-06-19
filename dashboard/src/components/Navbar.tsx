import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import {
  LayoutDashboard, Users, Activity, Shield, Bell,
  KeyRound, FileText, LogOut, ShieldCheck
} from 'lucide-react';

const NAV = [
  { to: '/',           icon: LayoutDashboard, label: 'Dashboard',  roles: [] },
  { to: '/employees',  icon: Users,            label: 'Employees',  roles: [] },
  { to: '/events',     icon: Activity,         label: 'Events',     roles: [] },
  { to: '/policies',   icon: Shield,           label: 'Policies',   roles: ['superadmin'] },
  { to: '/alerts',     icon: Bell,             label: 'Alerts',     roles: [] },
  { to: '/encryption', icon: KeyRound,         label: 'Encryption', roles: ['superadmin'] },
  { to: '/reports',    icon: FileText,         label: 'Reports',    roles: ['superadmin', 'analyst'] },
];

export default function Navbar() {
  const { user, logout, hasRole } = useAuth();
  const navigate = useNavigate();

  return (
    <aside className="navbar">
      <div className="navbar-brand">
        <ShieldCheck size={28} className="brand-icon" />
        <span className="brand-name">DataShield</span>
      </div>

      <nav className="navbar-nav">
        {NAV.filter(item => item.roles.length === 0 || item.roles.some(r => hasRole(r))).map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Icon size={18} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="navbar-footer">
        <div className="user-chip">
          <div className="user-avatar">{user?.full_name?.[0] ?? 'U'}</div>
          <div className="user-info">
            <span className="user-name">{user?.full_name}</span>
            <span className="user-role">{user?.role}</span>
          </div>
        </div>
        <button className="btn-logout" onClick={logout} title="Logout">
          <LogOut size={16} />
        </button>
      </div>
    </aside>
  );
}
