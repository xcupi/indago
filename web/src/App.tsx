import { TooltipProvider } from "@/components/ui/controls";
import Layout from "@/components/Layout";
import Dashboard from "@/pages/Dashboard";
import Projects from "@/pages/Projects";
import ProjectDetail from "@/pages/ProjectDetail";
import Scans from "@/pages/Scans";
import ScanDetail from "@/pages/ScanDetail";
import Settings from "@/pages/Settings";
import { FindingsPage, ReportsPage } from "@/pages/Collections";
import { useRoute } from "@/lib/router";

export default function App() {
  const route = useRoute();
  const [first, second] = route;

  let page: React.ReactNode;
  switch (first) {
    case "projects":
      page = second ? <ProjectDetail id={second} /> : <Projects />;
      break;
    case "scans":
      page = second ? <ScanDetail id={second} /> : <Scans />;
      break;
    case "findings":
      page = <FindingsPage />;
      break;
    case "reports":
      page = <ReportsPage />;
      break;
    case "settings":
      page = <Settings />;
      break;
    case "dashboard":
    case undefined:
      page = <Dashboard />;
      break;
    default:
      page = <Dashboard />;
  }

  return (
    <TooltipProvider>
      <Layout route={route}>{page}</Layout>
    </TooltipProvider>
  );
}
