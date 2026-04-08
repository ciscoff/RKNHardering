package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.PermissionRequestPlanner.Action
import org.junit.Assert.assertEquals
import org.junit.Test

class PermissionRequestPlannerTest {

    @Test
    fun `empty missing permissions returns none`() {
        assertEquals(Action.NONE, PermissionRequestPlanner.decideAction(emptyList()))
    }

    @Test
    fun `unrequested permission returns request`() {
        val action = PermissionRequestPlanner.decideAction(
            listOf(
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.ACCESS_FINE_LOCATION",
                    shouldShowRationale = false,
                    wasRequestedBefore = false,
                ),
            ),
        )

        assertEquals(Action.REQUEST, action)
    }

    @Test
    fun `permission with rationale returns show rationale`() {
        val action = PermissionRequestPlanner.decideAction(
            listOf(
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.ACCESS_FINE_LOCATION",
                    shouldShowRationale = true,
                    wasRequestedBefore = true,
                ),
            ),
        )

        assertEquals(Action.SHOW_RATIONALE, action)
    }

    @Test
    fun `fully blocked permissions return open settings`() {
        val action = PermissionRequestPlanner.decideAction(
            listOf(
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.ACCESS_FINE_LOCATION",
                    shouldShowRationale = false,
                    wasRequestedBefore = true,
                ),
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.POST_NOTIFICATIONS",
                    shouldShowRationale = false,
                    wasRequestedBefore = true,
                ),
            ),
        )

        assertEquals(Action.OPEN_SETTINGS, action)
    }

    @Test
    fun `mixed blocked and unrequested permissions still request`() {
        val action = PermissionRequestPlanner.decideAction(
            listOf(
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.POST_NOTIFICATIONS",
                    shouldShowRationale = false,
                    wasRequestedBefore = true,
                ),
                PermissionRequestPlanner.PermissionState(
                    permission = "android.permission.ACCESS_FINE_LOCATION",
                    shouldShowRationale = false,
                    wasRequestedBefore = false,
                ),
            ),
        )

        assertEquals(Action.REQUEST, action)
    }
}
