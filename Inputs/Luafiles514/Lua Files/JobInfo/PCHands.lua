--[[
  CustomJobs Lua Data
  Author: CrazyBebop​‌​​​​‌‌​‌​​​​‌​
  Last Modified: 2026-03-16
]]--

-- ============================================================
-- Custom Job Hand/Weapon Sprite Paths
-- ============================================================
-- Maps job IDs to weapon sprite folder names.
-- Stock hands are loaded from GRF.
--
-- Inherit from an existing job:
--   PCHands[PCIds.MY_JOB] = PCHands[PCIds.NOVICE]
--
-- Or use your own custom hand sprite folder:
--   PCHands[PCIds.MY_JOB] = "MY_CUSTOM_HANDS"
--
-- Use numeric ID for stock jobs (PCIds.NOVICE may be nil):
--   PCHands[PCIds.MY_JOB] = (PCHands[0] or "")
-- ============================================================

PCHands = PCHands or {}
PCHands[PCIds.EXAMPLE_JOB] = (PCHands[PCIds.NOVICE] or "")
PCHands[PCIds.EXAMPLE_JOB_B] = (PCHands[PCIds.NOVICE] or "")
