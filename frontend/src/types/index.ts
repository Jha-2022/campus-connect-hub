// Type definitions for the Campus Resource Management System

export type UserRole = 'admin' | 'organizer' | 'participant';

export interface User {
  id: string;
  email: string;
  name: string;
  avatar?: string;
  department: string;
  year: string;
  role: UserRole;
  clubs: string[];
  headOfClubs: string[];
  createdAt: Date;
}

export interface Club {
  id: string;
  name: string;
  description: string;
  logo?: string;
  category: ClubCategory;
  members: string[];
  coordinators: string[];
  head: string;
  createdAt: Date;
  isActive: boolean;
}

export type ClubCategory = 
  | 'technical' 
  | 'cultural' 
  | 'sports' 
  | 'social' 
  | 'academic' 
  | 'arts' 
  | 'other';

export type EventStatus = 
  | 'draft' 
  | 'pending_approval' 
  | 'approved' 
  | 'rejected' 
  | 'published' 
  | 'ongoing' 
  | 'completed' 
  | 'cancelled';

export interface Event {
  id: string;
  title: string;
  description: string;
  coverImage?: string;
  startDate: Date;
  endDate: Date;
  venue: string;
  status: EventStatus;
  organizers: string[]; // Club IDs
  createdBy: string; // User ID
  approvedBy?: string; // Admin User ID
  budget?: Budget;
  maxParticipants?: number;
  registeredParticipants: string[];
  tags: string[];
  isMultiDay: boolean;
  isCollaborative: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface Budget {
  estimated: number;
  approved?: number;
  spent: number;
  items: BudgetItem[];
}

export interface BudgetItem {
  id: string;
  description: string;
  amount: number;
  category: string;
  status: 'pending' | 'approved' | 'rejected' | 'spent';
}

export type ResourceType = 'room' | 'hall' | 'lab' | 'equipment';

export interface Resource {
  id: string;
  name: string;
  type: ResourceType;
  description: string;
  location: string;
  capacity?: number;
  amenities: string[];
  images: string[];
  isAvailable: boolean;
  requiresApproval: boolean;
  createdAt: Date;
}

export type BookingStatus = 
  | 'pending' 
  | 'approved' 
  | 'rejected' 
  | 'cancelled' 
  | 'completed';

export interface Booking {
  id: string;
  resourceId: string;
  resourceName: string;
  userId: string;
  eventId?: string;
  clubId?: string;
  startTime: Date;
  endTime: Date;
  purpose: string;
  status: BookingStatus;
  approvedBy?: string;
  notes?: string;
  createdAt: Date;
}

export interface Message {
  id: string;
  senderId: string;
  content: string;
  attachments?: string[];
  createdAt: Date;
  isRead: boolean;
}

export interface Chat {
  id: string;
  type: 'direct' | 'group' | 'event' | 'club';
  name?: string;
  participants: string[];
  messages: Message[];
  lastMessage?: Message;
  contextId?: string; // Event or Club ID for context-aware chats
  createdAt: Date;
}

export interface Notification {
  id: string;
  userId: string;
  title: string;
  message: string;
  type: NotificationType;
  isRead: boolean;
  actionUrl?: string;
  createdAt: Date;
}

export type NotificationType = 
  | 'event_approval' 
  | 'event_rejection' 
  | 'event_reminder' 
  | 'booking_status' 
  | 'new_message' 
  | 'club_invitation' 
  | 'system';

export interface DashboardStats {
  totalEvents: number;
  upcomingEvents: number;
  activeClubs: number;
  totalMembers: number;
  pendingApprovals: number;
  resourceUtilization: number;
}

export interface AnalyticsData {
  eventTrends: { month: string; count: number }[];
  clubActivity: { club: string; events: number; members: number }[];
  resourceUsage: { resource: string; hours: number }[];
  budgetOverview: { category: string; amount: number }[];
}
