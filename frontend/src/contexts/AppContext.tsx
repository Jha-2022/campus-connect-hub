import React, { createContext, useContext, useState, ReactNode } from 'react';
import { User, Notification, DashboardStats } from '@/types';

interface AppContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  notifications: Notification[];
  addNotification: (notification: Notification) => void;
  markNotificationRead: (id: string) => void;
  stats: DashboardStats;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean) => void;
}

const defaultStats: DashboardStats = {
  totalEvents: 24,
  upcomingEvents: 8,
  activeClubs: 12,
  totalMembers: 450,
  pendingApprovals: 5,
  resourceUtilization: 68,
};

const mockUser: User = {
  id: '1',
  email: 'john.doe@university.edu',
  name: 'John Doe',
  avatar: undefined,
  department: 'Computer Science',
  year: '3rd Year',
  role: 'admin',
  clubs: ['tech-club', 'coding-society'],
  headOfClubs: ['tech-club'],
  createdAt: new Date(),
};

const AppContext = createContext<AppContextType | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(mockUser);
  const [notifications, setNotifications] = useState<Notification[]>([
    {
      id: '1',
      userId: '1',
      title: 'Event Approved',
      message: 'Your event "Tech Summit 2024" has been approved.',
      type: 'event_approval',
      isRead: false,
      createdAt: new Date(),
    },
    {
      id: '2',
      userId: '1',
      title: 'New Booking Request',
      message: 'A new booking request for Auditorium is pending.',
      type: 'booking_status',
      isRead: false,
      createdAt: new Date(),
    },
  ]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const addNotification = (notification: Notification) => {
    setNotifications((prev) => [notification, ...prev]);
  };

  const markNotificationRead = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: true } : n))
    );
  };

  return (
    <AppContext.Provider
      value={{
        user,
        setUser,
        notifications,
        addNotification,
        markNotificationRead,
        stats: defaultStats,
        sidebarCollapsed,
        setSidebarCollapsed,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
}
