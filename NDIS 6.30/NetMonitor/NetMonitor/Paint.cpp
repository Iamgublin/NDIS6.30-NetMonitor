#include "Paint.h"
HWND  ListView, StatusBar, StaticWindow;
BOOL InitLvHead(HWND ListView)
{
	LV_COLUMN   lvColumn;
	int         i;
	TCHAR       szString[6][20] = { TEXT("timestamp"),
		TEXT("Source IP"),
		TEXT("Dest IP"),
		TEXT("Data Length"),
		TEXT("Protocol"),
		TEXT("imformation") };

	//initialize the columns
	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;//| LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;// ?? | LVCFMT_SPLITBUTTON;
	lvColumn.cx = 80;
	for (i = 0; i < 6; i++)
	{
		lvColumn.pszText = szString[i];
		if (i == 5)
		{
			lvColumn.cx = 200;
		}
		SendMessage(ListView, LVM_INSERTCOLUMN, (WPARAM)i, (LPARAM)&lvColumn);
	}
	//
	return TRUE;
}//

HWND CreateListView(HINSTANCE hInstance, HWND hwndParent)
{
	DWORD       dwStyle;
	BOOL        bSuccess = TRUE;
	// custom draw
	dwStyle = WS_TABSTOP | WS_CHILD | WS_BORDER | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS;
	//| LVS_EX_FULLROWSELECT  | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES| LVS_EX_INFOTIP | LVS_AUTOARRANGE | LVS_OWNERDATA;

	ListView = CreateWindowEx(WS_EX_WINDOWEDGE,//WS_EX_CLIENTEDGE,// ex style
		WC_LISTVIEW, // class name defined in commctrl.h
		NULL,                      // window text
		dwStyle,                   // style
		0,                         // x position
		0,                       // y position
		Cxrect,                  // width
		Cyrect/2,                 // height
		hwndParent,                // parent
		NULL,       // ID
		hInst, // instance
		NULL);                     // no extra data
								   //
	if (ListView)
	{
		ListView_SetExtendedListViewStyleEx(ListView, LVS_EX_FULLROWSELECT,
			LVS_EX_FULLROWSELECT);
		InitLvHead(ListView);

		//
		//HWND hwndHD=ListView_GetHeader(ListView); 
		//int  all=Header_GetItemCount(hwndHD);
		

		//RECT rc;
		//Header_GetItemRect(hwndHD,all-1,&rc);
		return ListView;
	}
	else
	{
		return NULL;
	}
}//
VOID supSetMenuIcon(
	HMENU hMenu,
	UINT Item,
	ULONG_PTR IconData
)
{
	MENUITEMINFO mii;
	RtlSecureZeroMemory(&mii, sizeof(mii));
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_BITMAP | MIIM_DATA;
	mii.hbmpItem = HBMMENU_CALLBACK;
	mii.dwItemData = IconData;
	SetMenuItemInfo(hMenu, Item, FALSE, &mii);
}

bool Paint(HWND hwnd)
{
	INITCOMMONCONTROLSEX    icc;
	icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
	if (!InitCommonControlsEx(&icc))
	{
		return FALSE;
	}

	RECT Rect;
	GetClientRect(hwnd, &Rect);
	Cxrect = Rect.right;
	Cyrect = Rect.bottom;
	CreateListView(hInst, hwnd);

	StatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
		WS_VISIBLE | WS_CHILD, 0, Cyrect, Cyrect, Cxrect-20, hwnd, NULL, hInst, NULL);

	StaticWindow = CreateWindowEx(0, WC_STATIC, NULL,
	WS_VISIBLE | WS_CHILD, 0 ,Cyrect/2, Cxrect, Cyrect/2, hwnd, NULL, hInst, NULL);

	/*ListViewInfo a[6] = { "asdasd","127.0.0.1","192.168.0.0","41","ARP","ASDDADAD" };
	for (int i = 0; i < 100; i++)
	{
		AddListView(a);
	}*/
	SetWindowText(StatusBar, "asdadas");
	HIMAGELIST ImageList = ImageList_LoadImage(hInst, MAKEINTRESOURCE(IDB_BITMAP3),
		16, 1, CLR_DEFAULT, IMAGE_BITMAP, LR_CREATEDIBSECTION);
	HMENU menu = GetSubMenu(GetMenu(HwndWinMain), 0);
	supSetMenuIcon(menu, ID_SELNETCARD,
		(ULONG_PTR)ImageList_ExtractIcon(hInst, ImageList, 0));
	/*HWND Splitter = CreateWindowEx(0, WC_STATIC, NULL,
		WS_VISIBLE | WS_CHILD, 0, 0, 100, 100, hwnd, NULL, hInst, NULL);*/
	return TRUE;
}
void InitAttackTreeView(HWND TreeView)
{
	LVCOLUMN lvColumn;
	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;
	lvColumn.cx = 120;
	SetWindowLong(TreeView, GWL_STYLE,
		WS_TABSTOP | WS_CHILD | WS_BORDER | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
	int         i;
	TCHAR       szString[2][20] = { TEXT("Target IP"),
		TEXT("Target MAC"),};
	for (i = 0; i < 2; i++)
	{
		lvColumn.pszText = szString[i];
		ListView_InsertColumn(TreeView, i, &lvColumn);
	}
	//
	return;
}
void InitSelCardTreeView(HWND TreeView)
{
	LVCOLUMN lvColumn;
	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;
	lvColumn.cx = 150;
	SetWindowLong(TreeView, GWL_STYLE,
		WS_TABSTOP | WS_CHILD | WS_BORDER | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS);
	TCHAR       szString[4][20] = { TEXT("NetCardName"),
		TEXT("Mac"),
		TEXT("DevPathName"),
		TEXT("IsFiltering") };
	for (int i = 0; i < 4; i++)
	{
		lvColumn.pszText = szString[i];
		if (i == 2)
		{
			lvColumn.cx = 200;
		}
		ListView_InsertColumn(TreeView, i, &lvColumn);
	}

}
