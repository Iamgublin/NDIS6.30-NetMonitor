#include"Winproc.h"
#include<windowsx.h>
INT_PTR CALLBACK MoreInformaiton(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	static int TrueIndex;
	switch (message)
	{
	case WM_INITDIALOG:
	{
		TrueIndex = (int)lParam;
		Button_SetCheck(GetDlgItem(hDlg, IDC_RADIO1), 1);
		ShowRawData(hDlg, TrueIndex);
		ShowMoreInformation(hDlg, TrueIndex);
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam)==IDC_RADIO1)
		{
			ShowRawData(hDlg, TrueIndex);
			return TRUE;
		}
		else if(LOWORD(wParam)==IDC_RADIO2)
		{
			ShowAnalysisData(hDlg, TrueIndex);
			return TRUE;
		}
	}
	return (INT_PTR)FALSE;
}
INT_PTR CALLBACK SelCard(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		InitSelCardTreeView(GetDlgItem(hDlg, IDC_CARDLIST));
		FindCard(hDlg);
		return (INT_PTR)FALSE;
	}
	case WM_PAINT:
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		int wmId = LOWORD(wParam);
		// 分析菜单选择: 
		switch (wmId)
		{
		case IDC_STOP:
			StopFilter(hDlg);
			EndDialog(hDlg, 0);
			break;
		case IDC_START:
			StartFilter(hDlg);
			EndDialog(hDlg, 0);
			break;
		default:
			break;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK Scan(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		IO_Packet Packet = { 0 };
		if (FilterHandle == NULL)
		{
			MessageBox(NULL, "请先打开网卡", "NetMonitor", MB_OK | MB_ICONINFORMATION);
		}
		ShowWindow(hDlg, SW_SHOW);
		UpdateWindow(hDlg);
		Net_ShowAdapter(FilterHandle, &Packet);
		UCHAR *Mac = Packet.Packet.ShowAdapter.AdapterInfo[StartIndex].MacAddress;
		char buf[20] = { 0 };
		sprintf_s(buf, "%02x-%02x-%02x-%02x-%02x-%02x\n", Mac[0], Mac[1], Mac[2], Mac[3], Mac[4], Mac[5]);
		SetDlgItemText(hDlg, IDC_MACADDRESS, buf);
		InitAttackTreeView(GetDlgItem(hDlg, IDC_ATTACKLIST));
		SetTimer(hDlg, 4, 5000, FindAttackTarget);
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			KillTimer(hDlg, 4);
			return (INT_PTR)TRUE;
		}
		int wmId = LOWORD(wParam);
		// 分析菜单选择: 
		switch (wmId)
		{
		case IDC_STARTSCAN:
			StartScan(hDlg);
			break;
		case IDC_ATTACK:
			Attack(hDlg);
			break;
		case IDC_DELETETARGET:
			DeleteAllTarget(hDlg);
			break;
		default:
			break;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目的:    处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_SIZE:
	{
		Cxrect = LOWORD(lParam);
		Cyrect = HIWORD(lParam);
		UpdateWindow(hWnd);
		break;
	}
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// 分析菜单选择: 
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		case ID_SELNETCARD:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_SELNETCARD), hWnd, SelCard);
			break;
		case ID_CLEARLIST:
			DeleteAllListInfo();
			break;
		case IDM_SCAN:
		{
			/*DialogBox(hInst, MAKEINTRESOURCE(IDD_SCAN), hWnd, Scan);*/
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_SCAN), hWnd, Scan);    //创建非模态对话框
		}
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: 在此处添加使用 hdc 的任何绘图代码...
		MoveWindow(ListView, 0, 0, Cxrect,
			Cyrect / 2, TRUE);
		MoveWindow(StaticWindow, 0, Cyrect / 2, Cxrect, Cyrect / 2, TRUE);
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_NOTIFY:
	{
		LPNMHDR Hdr = (LPNMHDR)lParam;
		if (Hdr->code == NM_CLICK)
		{
			ShowOutput((LPNMLISTVIEW)Hdr);
		}
		if (Hdr->code == NM_DBLCLK)
		{
			LPNMLISTVIEW Mlv = (LPNMLISTVIEW)Hdr;
			int index = Mlv->iItem;
			char temp[20] = { 0 };
			LV_ITEM Item;
			Item.iItem = index;
			Item.iSubItem = 0;
			Item.mask = LVFIF_TEXT;
			Item.pszText = temp;
			Item.cchTextMax = sizeof(temp);
			ListView_GetItem(Mlv->hdr.hwndFrom, &Item);
			int trueindex = atoi(temp);
			/*DialogBox(hInst, MAKEINTRESOURCE(IDD_MOREEINFORMATION), HwndWinMain, MoreInformaiton);*/
			DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_MOREEINFORMATION), HwndWinMain, MoreInformaiton, trueindex);
			break;
		}
		break;
	}
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
