--[[
  CustomJobs Lua Data
  Author: CrazyBebop​‌​​​​‌‌​‌​​​​‌​
  Last Modified: 2026-03-16
]]--

-- ============================================================
-- Custom Job Display Names
-- ============================================================
-- Stock job names are auto-populated from GRF (via PCFuncs.lua).
-- Only add entries here for:
--   1. Custom jobs (required)
--   2. Renaming existing jobs (optional)
--
-- To RENAME a stock job, use its numeric ID:
--   PCNames[4055] = "Dark Wizard"     -- Renames Warlock
--   PCNames[4054] = "Holy Knight"     -- Renames Rune Knight
--
-- For custom jobs, use PCIds:
--   PCNames[PCIds.MY_JOB] = "My Job"
--
-- Find job IDs at: https://github.com/rathena/rathena/blob/master/src/common/mmo.hpp
-- ============================================================

PCNames = PCNames or {}
PCNames[PCIds.EXAMPLE_JOB] = "Example Job"
PCNames[PCIds.EXAMPLE_JOB_B] = "Baby Example Job"
