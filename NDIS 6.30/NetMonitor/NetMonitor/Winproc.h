#pragma once
#include"global.h"
#include "Paint.h"
#include"..\..\NdisCoreApi\NdisCoreApi.h"
#include"..\..\RawPacketAnalysis\RawPacketAnalysis.h"
#include"ControlApi.h"
#pragma comment(lib,"..\\..\\lib\\RawPacketAnalysis.lib")
#pragma comment(lib,"..\\..\\lib\\NdisCoreApi.lib")
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
extern char pro[14][8];
extern BOOL InitLvHead(HWND ListView);
extern int AdapterNum;
extern int StartIndex;
