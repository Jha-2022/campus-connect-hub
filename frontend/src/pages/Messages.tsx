import { useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import {
  Search,
  Send,
  Plus,
  Users,
  MessageSquare,
  MoreVertical,
  Phone,
  Video,
  Paperclip,
  Smile,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface ChatPreview {
  id: string;
  name: string;
  avatar?: string;
  lastMessage: string;
  timestamp: string;
  unread: number;
  isOnline?: boolean;
  type: 'direct' | 'group' | 'club';
}

const mockChats: ChatPreview[] = [
  {
    id: '1',
    name: 'Tech Club',
    lastMessage: 'Meeting scheduled for tomorrow at 4 PM',
    timestamp: '2m ago',
    unread: 3,
    type: 'club',
  },
  {
    id: '2',
    name: 'Sarah Johnson',
    lastMessage: 'Thanks for the update!',
    timestamp: '15m ago',
    unread: 0,
    isOnline: true,
    type: 'direct',
  },
  {
    id: '3',
    name: 'Event Planning Team',
    lastMessage: 'Budget approved ✓',
    timestamp: '1h ago',
    unread: 5,
    type: 'group',
  },
  {
    id: '4',
    name: 'Mike Chen',
    lastMessage: 'Can you share the presentation?',
    timestamp: '3h ago',
    unread: 1,
    isOnline: false,
    type: 'direct',
  },
  {
    id: '5',
    name: 'Cultural Night Committee',
    lastMessage: 'Performer list finalized',
    timestamp: 'Yesterday',
    unread: 0,
    type: 'group',
  },
];

const mockMessages = [
  { id: '1', sender: 'John', content: 'Hey team! Quick update on Tech Summit.', time: '10:30 AM', isOwn: false },
  { id: '2', sender: 'You', content: 'Great! What\'s the latest?', time: '10:31 AM', isOwn: true },
  { id: '3', sender: 'Sarah', content: 'The venue is confirmed for March 15-17', time: '10:32 AM', isOwn: false },
  { id: '4', sender: 'John', content: 'Budget has been approved. We have ₹45,000 to work with.', time: '10:33 AM', isOwn: false },
  { id: '5', sender: 'You', content: 'Perfect! I\'ll start reaching out to speakers.', time: '10:35 AM', isOwn: true },
  { id: '6', sender: 'Mike', content: 'Meeting scheduled for tomorrow at 4 PM', time: '10:40 AM', isOwn: false },
];

export default function Messages() {
  const [selectedChat, setSelectedChat] = useState<ChatPreview | null>(mockChats[0]);
  const [messageInput, setMessageInput] = useState('');

  return (
    <MainLayout title="Messages" subtitle="Stay connected with your teams">
      <div className="flex h-[calc(100vh-8rem)] gap-4 animate-fade-in">
        {/* Chat List */}
        <div className="w-80 flex-shrink-0 rounded-xl border border-border bg-card">
          <div className="border-b border-border p-4">
            <div className="flex items-center justify-between">
              <h2 className="font-display font-semibold">Conversations</h2>
              <Button size="icon" variant="ghost" className="h-8 w-8">
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            <div className="relative mt-3">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search messages..."
                className="bg-secondary pl-9"
              />
            </div>
          </div>
          <ScrollArea className="h-[calc(100%-5rem)]">
            <div className="p-2">
              {mockChats.map((chat) => (
                <button
                  key={chat.id}
                  onClick={() => setSelectedChat(chat)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg p-3 text-left transition-colors',
                    selectedChat?.id === chat.id
                      ? 'bg-primary-light'
                      : 'hover:bg-muted/50'
                  )}
                >
                  <div className="relative">
                    <Avatar className="h-10 w-10">
                      <AvatarImage src={chat.avatar} />
                      <AvatarFallback className="bg-primary text-primary-foreground">
                        {chat.type === 'club' || chat.type === 'group' ? (
                          <Users className="h-4 w-4" />
                        ) : (
                          chat.name.charAt(0)
                        )}
                      </AvatarFallback>
                    </Avatar>
                    {chat.isOnline && (
                      <span className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-card bg-success" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between">
                      <p className="truncate font-medium text-foreground">
                        {chat.name}
                      </p>
                      <span className="text-xs text-muted-foreground">
                        {chat.timestamp}
                      </span>
                    </div>
                    <p className="truncate text-sm text-muted-foreground">
                      {chat.lastMessage}
                    </p>
                  </div>
                  {chat.unread > 0 && (
                    <Badge className="h-5 min-w-5 justify-center bg-primary text-xs text-primary-foreground">
                      {chat.unread}
                    </Badge>
                  )}
                </button>
              ))}
            </div>
          </ScrollArea>
        </div>

        {/* Chat Area */}
        {selectedChat ? (
          <div className="flex flex-1 flex-col rounded-xl border border-border bg-card">
            {/* Chat Header */}
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div className="flex items-center gap-3">
                <Avatar className="h-10 w-10">
                  <AvatarFallback className="bg-primary text-primary-foreground">
                    {selectedChat.type === 'club' || selectedChat.type === 'group' ? (
                      <Users className="h-4 w-4" />
                    ) : (
                      selectedChat.name.charAt(0)
                    )}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <p className="font-medium">{selectedChat.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {selectedChat.type === 'group' || selectedChat.type === 'club'
                      ? '8 members'
                      : selectedChat.isOnline
                      ? 'Online'
                      : 'Offline'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <Button variant="ghost" size="icon" className="h-8 w-8">
                  <Phone className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8">
                  <Video className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8">
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {/* Messages */}
            <ScrollArea className="flex-1 p-4">
              <div className="space-y-4">
                {mockMessages.map((message) => (
                  <div
                    key={message.id}
                    className={cn(
                      'flex',
                      message.isOwn ? 'justify-end' : 'justify-start'
                    )}
                  >
                    <div
                      className={cn(
                        'max-w-[70%] rounded-2xl px-4 py-2',
                        message.isOwn
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted text-foreground'
                      )}
                    >
                      {!message.isOwn && (
                        <p className="mb-1 text-xs font-medium text-primary">
                          {message.sender}
                        </p>
                      )}
                      <p className="text-sm">{message.content}</p>
                      <p
                        className={cn(
                          'mt-1 text-right text-xs',
                          message.isOwn
                            ? 'text-primary-foreground/70'
                            : 'text-muted-foreground'
                        )}
                      >
                        {message.time}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>

            {/* Message Input */}
            <div className="border-t border-border p-4">
              <div className="flex items-center gap-2">
                <Button variant="ghost" size="icon" className="h-9 w-9 flex-shrink-0">
                  <Paperclip className="h-4 w-4" />
                </Button>
                <Input
                  placeholder="Type a message..."
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  className="bg-secondary"
                />
                <Button variant="ghost" size="icon" className="h-9 w-9 flex-shrink-0">
                  <Smile className="h-4 w-4" />
                </Button>
                <Button
                  size="icon"
                  className="h-9 w-9 flex-shrink-0 bg-primary text-primary-foreground hover:bg-primary-hover"
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center rounded-xl border border-border bg-card">
            <div className="text-center">
              <MessageSquare className="mx-auto h-12 w-12 text-muted-foreground" />
              <h3 className="mt-4 font-display text-lg font-semibold">
                Select a conversation
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Choose a chat from the list to start messaging
              </p>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
