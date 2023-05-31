package main

/*
#cgo LDFLAGS: -L ./ -lkindling  -lstdc++ -ldl
#cgo CFLAGS: -I .
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "cgo_func.h"
*/
import "C"
import (
	"fmt"
	"log"
	"time"
	"unsafe"
)

type CKindlingEventForGo C.struct_kindling_event_t_for_go
type CEventParamsForSubscribe C.struct_event_params_for_subscribe

func Start() error {
	log.Printf("Start CgoReceiver")
	res := int(C.runForGo())
	if res == 1 {
		return fmt.Errorf("fail to init probe")
	}
	// 开启内核事件获取监控
	go getCaptureStatistics()

	time.Sleep(2 * time.Second)

	// 订阅内核事件，只有订阅的事件才能获取
	subEvent()
	// Wait for the C routine running
	time.Sleep(2 * time.Second)
	C.startProfile()
	//获取内核事件
	GetKindlingEvents()
	return nil
}

func getCaptureStatistics() {
	C.getCaptureStatistics()
}

func subEvent() error {
	subscribeInfo := []SubEvent{
		{Name: "tracepoint-cpu_analysis"},
	}
	if len(subscribeInfo) == 0 {
		log.Println("No events are subscribed by cgo receiver. Please check your configuration.")
	} else {
		log.Println("The subscribed events are: ", subscribeInfo)
	}
	for _, value := range subscribeInfo {
		//to do. analyze params filed in the value
		paramsList := make([]CEventParamsForSubscribe, 0)
		var temp CEventParamsForSubscribe
		temp.name = C.CString("terminator")
		paramsList = append(paramsList, temp)
		csName := C.CString(value.Name)
		csCategory := C.CString(value.Category)
		C.subEventForGo(csName, csCategory, (unsafe.Pointer)(&paramsList[0]))
		C.free(unsafe.Pointer(csName))
		C.free(unsafe.Pointer(csCategory))
	}
	return nil
}

func GetKindlingEvents() {
	var count int = 0
	npKindlingEvent := make([]CKindlingEventForGo, 1000)
	C.initKindlingEventForGo(C.int(1000), (unsafe.Pointer)(&npKindlingEvent[0]))

	for {
		res := int(C.getEventsByInterval(C.int(100000000), (unsafe.Pointer)(&npKindlingEvent[0]), (unsafe.Pointer)(&count)))
		if res == 0 {
			//for i := 0; i < count; i++ {
			//	event := convertEvent((*CKindlingEventForGo)(&npKindlingEvent[i]))
			//	log.Printf("event :", event)
			//}
			//r.telemetry.Logger.Info("total_number_of_kindling_events: ", zap.Int("num", count))
		}
		count = 0
	}
}

func convertEvent(cgoEvent *CKindlingEventForGo) *KindlingEvent {
	ev := new(KindlingEvent)
	ev.Timestamp = uint64(cgoEvent.timestamp)
	ev.Name = C.GoString(cgoEvent.name)
	ev.Category = Category(cgoEvent.category)
	ev.Ctx.ThreadInfo.Pid = uint32(cgoEvent.context.tinfo.pid)
	ev.Ctx.ThreadInfo.Tid = uint32(cgoEvent.context.tinfo.tid)
	ev.Ctx.ThreadInfo.Uid = uint32(cgoEvent.context.tinfo.uid)
	ev.Ctx.ThreadInfo.Gid = uint32(cgoEvent.context.tinfo.gid)
	ev.Ctx.ThreadInfo.Comm = C.GoString(cgoEvent.context.tinfo.comm)
	ev.Ctx.ThreadInfo.ContainerId = C.GoString(cgoEvent.context.tinfo.containerId)
	ev.Ctx.FdInfo.Protocol = L4Proto(cgoEvent.context.fdInfo.protocol)
	ev.Ctx.FdInfo.Num = int32(cgoEvent.context.fdInfo.num)
	ev.Ctx.FdInfo.TypeFd = FDType(cgoEvent.context.fdInfo.fdType)
	ev.Ctx.FdInfo.Filename = C.GoString(cgoEvent.context.fdInfo.filename)
	ev.Ctx.FdInfo.Directory = C.GoString(cgoEvent.context.fdInfo.directory)
	ev.Ctx.FdInfo.Role = If(cgoEvent.context.fdInfo.role != 0, true, false).(bool)
	ev.Ctx.FdInfo.Sip = make([]uint32, 4)
	ev.Ctx.FdInfo.Dip = make([]uint32, 4)
	for i := 0; i < 4; i++ {
		ev.Ctx.FdInfo.Sip[i] = uint32(cgoEvent.context.fdInfo.sip[i])
		ev.Ctx.FdInfo.Dip[i] = uint32(cgoEvent.context.fdInfo.dip[i])
	}
	ev.Ctx.FdInfo.Sport = uint32(cgoEvent.context.fdInfo.sport)
	ev.Ctx.FdInfo.Dport = uint32(cgoEvent.context.fdInfo.dport)
	ev.Ctx.FdInfo.Source = uint64(cgoEvent.context.fdInfo.source)
	ev.Ctx.FdInfo.Destination = uint64(cgoEvent.context.fdInfo.destination)

	ev.ParamsNumber = uint16(cgoEvent.paramsNumber)
	ev.Latency = uint64(cgoEvent.latency)
	for i := 0; i < int(ev.ParamsNumber); i++ {
		ev.UserAttributes[i].Key = C.GoString(cgoEvent.userAttributes[i].key)
		userAttributesLen := cgoEvent.userAttributes[i].len
		ev.UserAttributes[i].Value = C.GoBytes(unsafe.Pointer(cgoEvent.userAttributes[i].value), C.int(userAttributesLen))
		ev.UserAttributes[i].ValueType = ValueType(cgoEvent.userAttributes[i].valueType)
	}
	return ev
}

func If(condition bool, trueVal, falseVal interface{}) interface{} {
	if condition {
		return trueVal
	}
	return falseVal
}
