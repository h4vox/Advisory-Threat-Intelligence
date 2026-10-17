import { createRouter } from "@tanstack/react-router";
import { AppErrorComponent } from "@/lib/error-component";
import { installProcessGuards } from "@/lib/process-guards";
import { routeTree } from "./routeTree.gen";

// Server start-up: log background promise failures instead of exiting (see process-guards).
installProcessGuards();

export function getRouter() {
  return createRouter({
    routeTree,
    defaultErrorComponent: AppErrorComponent,
    defaultPreload: "intent",
    defaultPreloadDelay: 50,
    defaultPreloadStaleTime: 60_000,
  });
}
