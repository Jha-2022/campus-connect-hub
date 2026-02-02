# campusHub
CampusHub is a comprehensive digital ecosystem designed to centralize and enhance the university experience for students and faculty. By integrating club management, academic resource sharing, event coordination, and real-time communication into a single unified platform, it streamlines campus life and fosters a more connected academic community. Built with a modern React frontend and a robust Node.js backend, the platform provides intuitive dashboards and data insights to help students navigate their campus journey more effectively.

## Project Demo
https://github.com/user-attachments/assets/04c80b66-0798-4233-a825-bfa89170a846

## Some Insight Glimpses
🏁 Getting Started

Prerequisites

Node.js (Latest LTS recommended)

npm or bun

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone https://github.com/Jha-2022/campus-connect-hub.git

# Step 2: Navigate to the project directory.
cd campus-connect-hub

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```
## Zip File
[campusHub.zip](https://github.com/user-attachments/files/25011753/697e49dfab842_hackoverflow.zip)


## Features and Folder Structure for this project?
```sh
campusHub/
├── backend/
│   ├── .env                    # Environment variables
│   ├── package.json            # Backend dependencies and scripts
│   └── server.js               # Entry point for the Express/Node server
├── frontend/
│   ├── public/                 # Static assets
│   │   ├── placeholder.svg
│   │   └── robots.txt
│   ├── src/
│   │   ├── components/         # React components
│   │   │   ├── analytics/      # Charts and data visualization
│   │   │   ├── clubs/          # Club management components
│   │   │   ├── dashboard/      # Overview widgets
│   │   │   ├── events/         # Event cards and lists
│   │   │   ├── layout/         # Header, Sidebar, and MainLayout
│   │   │   ├── resources/      # Academic resource components
│   │   │   ├── ui/             # Reusable Shadcn UI primitives
│   │   │   └── NavLink.tsx
│   │   ├── contexts/           # AppContext for global state
│   │   ├── hooks/              # Custom hooks (toast, mobile detection)
│   │   ├── lib/                # Utilities and mock data
│   │   ├── pages/              # Main view components (Dashboard, Clubs, etc.)
│   │   ├── test/               # Vitest configuration and example tests
│   │   ├── types/              # TypeScript definitions
│   │   ├── App.css
│   │   ├── App.tsx             # Main application component
│   │   ├── index.css           # Global styles
│   │   ├── main.tsx            # React entry point
│   │   └── vite-env.d.ts
│   ├── .gitignore
│   ├── components.json         # Shadcn configuration
│   ├── eslint.config.js
│   ├── index.html              # HTML entry point
│   ├── package.json            # Frontend dependencies
│   ├── package-lock.json
│   ├── postcss.config.js
│   ├── tailwind.config.ts      # Styling configuration
│   ├── tsconfig.json           # TypeScript configuration
│   ├── tsconfig.app.json
│   ├── tsconfig.node.json
│   ├── vite.config.ts          # Vite build tool configuration
│   └── vitest.config.ts        # Test runner configuration
├── .gitignore
├── bun.lockb                   # Bun lockfile
├── LICENSE                     # MIT License
└── README.md                   # Project documentation
```
🚀 Features

- Dashboard: Centralized view of campus activities, upcoming events, and personal statistics.

- Clubs & Organizations: Discover, join, and manage campus clubs with dedicated profiles and member lists.

- Event Management: Browse upcoming campus events, RSVP, and track your schedule.

- Resource Center: Access and share academic materials, campus guides, and helpful links.

- Analytics: Visualized data insights for student engagement and club performance.

- Messaging: Built-in communication tools for collaboration between students and organizations.

## What technologies are used for this project?

🛠️ Tech Stack

- Framework: React
- Build Tool: Vite
- Language: TypeScript
- Styling: Tailwind CSS
- UI Components: shadcn/ui (Radix UI)
- Icons: Lucide React
- Charts: Recharts
- Testing: Vitest


## Heres the deployed Vercel Link
https://campus-connect-hub-lyart.vercel.app/


📝 License

This project is licensed under the MIT License.
