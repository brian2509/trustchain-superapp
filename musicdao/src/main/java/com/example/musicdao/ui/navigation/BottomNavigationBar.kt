package com.example.musicdao.ui

import androidx.compose.material.BottomNavigation
import androidx.compose.material.BottomNavigationItem
import androidx.compose.material.Icon
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavHostController
import com.example.musicdao.ui.navigation.Screen

@Composable
fun BottomNavigationBar(navController: NavHostController) {

    var selectedBottomBarIndex by remember { mutableStateOf(0) }

    data class BottomNavigationItem(val label: String, val route: String, val icon: ImageVector)

    val items = listOf(
        BottomNavigationItem("Home", Screen.Home.route, Icons.Filled.Home),
        BottomNavigationItem("Artists", Screen.DiscoverArtists.route, Icons.Filled.Person),
        BottomNavigationItem("Search", Screen.Search.route, Icons.Filled.Search),
        BottomNavigationItem("Torrents", Screen.Debug.route, Icons.Filled.Send),
        BottomNavigationItem("Creator", Screen.CreatorMenu.route, Icons.Filled.Person),
    )

    BottomNavigation {
        items.forEachIndexed { index, s ->
            BottomNavigationItem(
                selected = selectedBottomBarIndex == index,
                onClick = {
                    selectedBottomBarIndex = index
                    navController.navigate(s.route)
                },
                icon = { Icon(s.icon, contentDescription = null) },
                label = { Text(s.label) },
            )
        }
    }
}
