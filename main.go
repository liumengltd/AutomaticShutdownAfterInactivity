package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LASTINPUTINFO structure for tracking last input time
type LASTINPUTINFO struct {
	CbSize uint32
	DwTime uint32
}

// Windows API function declarations
var (
	user32                = syscall.NewLazyDLL("user32.dll")
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetLastInputInfo  = user32.NewProc("GetLastInputInfo")
	procGetTickCount      = kernel32.NewProc("GetTickCount")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
)

// GetLastInputInfo retrieves the time of the last input event
func GetLastInputInfo(plii *LASTINPUTINFO) bool {
	ret, _, _ := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(plii)))
	return ret != 0
}

// GetTickCount retrieves the number of milliseconds that have elapsed since the system was started
func GetTickCount() uint32 {
	ret, _, _ := procGetTickCount.Call()
	return uint32(ret)
}

// GetCurrentProcessHandle returns a handle to the current process
func GetCurrentProcessHandle() windows.Handle {
	ret, _, _ := procGetCurrentProcess.Call()
	return windows.Handle(ret)
}

var (
	lastInputInfo LASTINPUTINFO
	logger        *log.Logger
	logFile       *os.File

	// 定时器相关变量
	shutdownTimer     *time.Timer
	shutdownTimerLock sync.Mutex
	lastActivity      time.Time
)

func init() {
	lastInputInfo.CbSize = uint32(unsafe.Sizeof(lastInputInfo))

	// 设置日志文件
	var err error
	logFile, err = os.OpenFile("auto_shutdown.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("无法创建日志文件: %v\n", err)
		return
	}

	// 配置日志记录器
	logger = log.New(logFile, "", log.Ldate|log.Ltime)
	logger.Println("程序启动")

	// 初始化最后活动时间
	lastActivity = time.Now()
}

func logAndPrint(message string) {
	fmt.Println(message)
	if logger != nil {
		logger.Println(message)
	}
}

// 检查是否有新的输入活动
func checkForNewActivity() bool {
	// 获取当前滴答计数
	currentTick := GetTickCount()

	// 获取上次输入时间
	success := GetLastInputInfo(&lastInputInfo)
	if !success {
		logAndPrint("警告: 获取最后输入信息失败")
		return false
	}

	// 计算空闲时间
	lastInputTick := lastInputInfo.DwTime
	idleTickCount := currentTick - lastInputTick
	idleTime := time.Duration(idleTickCount) * time.Millisecond

	// 记录详细的计算过程
	if logger != nil {
		logger.Printf("空闲时间计算: 当前滴答=%d, 上次输入滴答=%d, 差值=%d毫秒, 转换为分钟=%.2f",
			currentTick, lastInputTick, idleTickCount, idleTime.Minutes())
	}

	// 检查是否有新活动（与上次记录的活动时间比较）
	newLastActivity := time.Now().Add(-idleTime)
	hasNewActivity := newLastActivity.After(lastActivity)

	if hasNewActivity {
		logAndPrint(fmt.Sprintf("检测到新活动，重置定时器。上次活动时间: %s, 新活动时间: %s",
			lastActivity.Format("15:04:05"), newLastActivity.Format("15:04:05")))
		lastActivity = newLastActivity
	}

	return hasNewActivity
}

// 停止当前的关机定时器（如果存在）
func stopShutdownTimer() {
	shutdownTimerLock.Lock()
	defer shutdownTimerLock.Unlock()

	if shutdownTimer != nil {
		if !shutdownTimer.Stop() {
			// 尝试消耗通道中的值（如果定时器已经触发但还未被处理）
			select {
			case <-shutdownTimer.C:
			default:
			}
		}
		shutdownTimer = nil
		logAndPrint("关机定时器已停止")
	}
}

// 启动新的关机定时器
func startShutdownTimer(duration time.Duration) {
	shutdownTimerLock.Lock()
	defer shutdownTimerLock.Unlock()

	// 先停止现有的定时器
	if shutdownTimer != nil {
		if !shutdownTimer.Stop() {
			// 尝试消耗通道中的值
			select {
			case <-shutdownTimer.C:
			default:
			}
		}
	}

	logAndPrint(fmt.Sprintf("启动新的关机定时器，持续时间: %v", duration))

	// 创建新的定时器
	shutdownTimer = time.NewTimer(duration)

	// 在新的goroutine中等待定时器触发
	go func() {
		<-shutdownTimer.C
		logAndPrint("关机定时器触发，系统将关机")
		shutdownSystem()
	}()
}

func getIdleTime() time.Duration {
	// 获取当前滴答计数
	currentTick := GetTickCount()

	// 获取上次输入时间
	success := GetLastInputInfo(&lastInputInfo)
	if !success {
		logAndPrint("警告: 获取最后输入信息失败")
		return 0
	}

	// 计算空闲时间
	lastInputTick := lastInputInfo.DwTime
	idleTickCount := currentTick - lastInputTick
	idleTime := time.Duration(idleTickCount) * time.Millisecond

	return idleTime
}

func shutdownSystem() {
	logAndPrint("系统即将关机...")

	// Create a process token with shutdown privilege
	var token windows.Token

	// Get current process handle directly using our function
	currentProcess := GetCurrentProcessHandle()

	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		logAndPrint(fmt.Sprintf("无法获取进程令牌: %v", err))
		return
	}
	defer func(token windows.Token) {
		_ = token.Close()
	}(token)

	// Enable shutdown privilege
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeShutdownPrivilege"), &luid)
	if err != nil {
		logAndPrint(fmt.Sprintf("无法查找关机权限: %v", err))
		return
	}

	var privileges windows.Tokenprivileges
	privileges.PrivilegeCount = 1
	privileges.Privileges[0].Luid = luid
	privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	err = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	if err != nil {
		logAndPrint(fmt.Sprintf("无法调整令牌权限: %v", err))
		return
	}

	// Execute shutdown command
	cmd := exec.Command("shutdown", "/s", "/t", "60", "/c", "系统长时间无活动，即将关机")
	err = cmd.Run()
	if err != nil {
		logAndPrint(fmt.Sprintf("关机命令执行失败: %v", err))
		return
	}
}

// TimeRange 时间范围结构体
type TimeRange struct {
	StartHour   int
	StartMinute int
	EndHour     int
	EndMinute   int
}

// parseStartParam 解析开始时间参数，支持"HH:MM"和"HH:MM-HH:MM"两种格式
func parseStartParam(startStr string) (TimeRange, error) {
	var timeRange TimeRange
	timeRange.EndHour = -1   // 默认值，表示没有结束时间
	timeRange.EndMinute = -1 // 默认值，表示没有结束时间

	// 检查是否包含"-"，表示时间范围
	if strings.Contains(startStr, "-") {
		parts := strings.Split(startStr, "-")
		if len(parts) != 2 {
			return timeRange, fmt.Errorf("无效的时间范围格式，应为'HH:MM-HH:MM'，例如'22:00-23:30'")
		}

		// 解析开始时间
		startTime := strings.TrimSpace(parts[0])
		startTimeParts := strings.Split(startTime, ":")
		if len(startTimeParts) != 2 {
			return timeRange, fmt.Errorf("无效的开始时间格式，应为'HH:MM'，例如'22:00'")
		}

		startHour, err := strconv.Atoi(startTimeParts[0])
		if err != nil {
			return timeRange, fmt.Errorf("无效的开始小时: %v", err)
		}
		if startHour < 0 || startHour > 23 {
			return timeRange, fmt.Errorf("开始小时必须在0-23之间")
		}

		startMinute, err := strconv.Atoi(startTimeParts[1])
		if err != nil {
			return timeRange, fmt.Errorf("无效的开始分钟: %v", err)
		}
		if startMinute < 0 || startMinute > 59 {
			return timeRange, fmt.Errorf("开始分钟必须在0-59之间")
		}

		// 解析结束时间
		endTime := strings.TrimSpace(parts[1])
		endTimeParts := strings.Split(endTime, ":")
		if len(endTimeParts) != 2 {
			return timeRange, fmt.Errorf("无效的结束时间格式，应为'HH:MM'，例如'23:30'")
		}

		endHour, err := strconv.Atoi(endTimeParts[0])
		if err != nil {
			return timeRange, fmt.Errorf("无效的结束小时: %v", err)
		}
		if endHour < 0 || endHour > 23 {
			return timeRange, fmt.Errorf("结束小时必须在0-23之间")
		}

		endMinute, err := strconv.Atoi(endTimeParts[1])
		if err != nil {
			return timeRange, fmt.Errorf("无效的结束分钟: %v", err)
		}
		if endMinute < 0 || endMinute > 59 {
			return timeRange, fmt.Errorf("结束分钟必须在0-59之间")
		}

		// 确保开始时间小于结束时间
		startTotalMinutes := startHour*60 + startMinute
		endTotalMinutes := endHour*60 + endMinute

		if startTotalMinutes >= endTotalMinutes {
			return timeRange, fmt.Errorf("开始时间必须早于结束时间")
		}

		timeRange.StartHour = startHour
		timeRange.StartMinute = startMinute
		timeRange.EndHour = endHour
		timeRange.EndMinute = endMinute
	} else {
		// 单个时间点
		timeParts := strings.Split(strings.TrimSpace(startStr), ":")
		if len(timeParts) != 2 {
			return timeRange, fmt.Errorf("无效的时间格式，应为'HH:MM'，例如'22:00'")
		}

		hour, err := strconv.Atoi(timeParts[0])
		if err != nil {
			return timeRange, fmt.Errorf("无效的小时: %v", err)
		}
		if hour < 0 || hour > 23 {
			return timeRange, fmt.Errorf("小时必须在0-23之间")
		}

		minute, err := strconv.Atoi(timeParts[1])
		if err != nil {
			return timeRange, fmt.Errorf("无效的分钟: %v", err)
		}
		if minute < 0 || minute > 59 {
			return timeRange, fmt.Errorf("分钟必须在0-59之间")
		}

		timeRange.StartHour = hour
		timeRange.StartMinute = minute
	}

	return timeRange, nil
}

// shouldStartMonitoring 判断是否应该开始监控
func shouldStartMonitoring(timeRange TimeRange) bool {
	now := time.Now()
	currentHour := now.Hour()
	currentMinute := now.Minute()
	currentTotalMinutes := currentHour*60 + currentMinute

	// 如果是单个时间点模式（没有结束时间）
	if timeRange.EndHour == -1 {
		// 如果当前时间晚于或等于指定时间点，则开始监控
		startTotalMinutes := timeRange.StartHour*60 + timeRange.StartMinute
		return currentTotalMinutes >= startTotalMinutes
	}

	// 如果是时间范围模式
	// 检查当前时间是否在时间范围内
	startTotalMinutes := timeRange.StartHour*60 + timeRange.StartMinute
	endTotalMinutes := timeRange.EndHour*60 + timeRange.EndMinute

	return currentTotalMinutes >= startTotalMinutes && currentTotalMinutes <= endTotalMinutes
}

// shouldStopMonitoring 判断是否应该停止监控
func shouldStopMonitoring(timeRange TimeRange, monitoringStartDate time.Time) bool {
	now := time.Now()

	// 如果是单个时间点模式（没有结束时间）
	if timeRange.EndHour == -1 {
		// 如果当前时间已经是第二天，则停止监控
		return now.Day() != monitoringStartDate.Day() ||
			now.Month() != monitoringStartDate.Month() ||
			now.Year() != monitoringStartDate.Year()
	}

	// 如果是时间范围模式
	currentHour := now.Hour()
	currentMinute := now.Minute()
	currentTotalMinutes := currentHour*60 + currentMinute
	endTotalMinutes := timeRange.EndHour*60 + timeRange.EndMinute

	// 如果当前时间超过了结束时间，或者是第二天，则停止监控
	if currentTotalMinutes > endTotalMinutes {
		return true
	}

	// 如果当前日期不是监控开始的日期，也停止监控
	if now.Day() != monitoringStartDate.Day() ||
		now.Month() != monitoringStartDate.Month() ||
		now.Year() != monitoringStartDate.Year() {
		return true
	}

	return false
}

func main() {
	// 定义命令行参数
	inactivityThreshold := flag.Int("idle", 30, "无活动自动关机的时间（分钟）")
	startParam := flag.String("time"+
		"", "22:00", "开始监控的时间，支持单个时间点(如\"22:00\")或时间范围(如\"22:00-23:30\")")
	createTask := flag.Bool("task", false, "创建Windows任务计划，在系统启动时自动运行")
	checkInterval := flag.Int("interval", 10, "检查系统活动的间隔（秒）")
	flag.Parse()

	// 解析开始时间参数
	timeRange, err := parseStartParam(*startParam)
	if err != nil {
		logAndPrint(fmt.Sprintf("解析开始时间参数错误: %v", err))
		os.Exit(1)
	}

	// 如果启用了task参数，创建任务计划后退出
	if *createTask {
		err := createScheduledTask(os.Args[1:])
		if err != nil {
			logAndPrint(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	logAndPrint(fmt.Sprintf("自动关机程序已启动"))

	// 根据时间范围类型显示不同的设置信息
	if timeRange.EndHour == -1 {
		logAndPrint(fmt.Sprintf("设置：\n- 监控开始时间: %02d:%02d\n- 无活动关机时间: %d分钟\n- 检查间隔: %d秒",
			timeRange.StartHour, timeRange.StartMinute, *inactivityThreshold, *checkInterval))
	} else {
		logAndPrint(fmt.Sprintf("设置：\n- 监控时间范围: %02d:%02d - %02d:%02d\n- 无活动关机时间: %d分钟\n- 检查间隔: %d秒",
			timeRange.StartHour, timeRange.StartMinute, timeRange.EndHour, timeRange.EndMinute, *inactivityThreshold, *checkInterval))
	}

	// 主循环
	ticker := time.NewTicker(time.Duration(*checkInterval) * time.Second)
	defer ticker.Stop()

	// 程序退出时关闭日志文件
	defer func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}()

	var monitoring = false
	var monitoringStartDate time.Time
	var timerActive = false

	for range ticker.C {
		now := time.Now()

		// 检查是否应该开始监控
		if !monitoring && shouldStartMonitoring(timeRange) {
			monitoring = true
			monitoringStartDate = now
			lastActivity = now // 初始化最后活动时间

			// 根据时间范围类型显示不同的开始监控信息
			if timeRange.EndHour == -1 {
				logAndPrint(fmt.Sprintf("[%s] 开始监控系统活动...", now.Format("2006-01-02 15:04:05")))
			} else {
				logAndPrint(fmt.Sprintf("[%s] 开始监控系统活动，将持续到 %02d:%02d...",
					now.Format("2006-01-02 15:04:05"), timeRange.EndHour, timeRange.EndMinute))
			}
		}

		// 检查是否应该停止监控
		if monitoring && shouldStopMonitoring(timeRange, monitoringStartDate) {
			monitoring = false
			stopShutdownTimer() // 停止任何活动的定时器
			timerActive = false

			// 根据时间范围类型显示不同的停止监控信息
			if timeRange.EndHour == -1 {
				logAndPrint(fmt.Sprintf("[%s] 已经到第二天，停止监控", now.Format("2006-01-02 15:04:05")))
			} else {
				logAndPrint(fmt.Sprintf("[%s] 已经超过监控结束时间 %02d:%02d，停止监控",
					now.Format("2006-01-02 15:04:05"), timeRange.EndHour, timeRange.EndMinute))
			}
			continue
		}

		// 如果正在监控，检查系统活动
		if monitoring {
			// 检查是否有新的输入活动
			hasNewActivity := checkForNewActivity()

			if hasNewActivity {
				// 如果有新活动，停止当前的关机定时器
				if timerActive {
					stopShutdownTimer()
					timerActive = false
					logAndPrint(fmt.Sprintf("[%s] 检测到用户活动，取消关机定时器", now.Format("2006-01-02 15:04:05")))
				}
			}

			// 如果没有活动的定时器，启动一个新的
			if !timerActive {
				// 启动一个新的关机定时器
				shutdownDuration := time.Duration(*inactivityThreshold) * time.Minute
				startShutdownTimer(shutdownDuration)
				timerActive = true
				logAndPrint(fmt.Sprintf("[%s] 启动关机定时器，如果 %d 分钟内无活动将关机",
					now.Format("2006-01-02 15:04:05"), *inactivityThreshold))
			}

			// 显示当前空闲时间（仅用于日志记录）
			idleTime := getIdleTime()
			logAndPrint(fmt.Sprintf("[%s] 当前无活动时间: %.2f 分钟 (阈值: %d 分钟)",
				now.Format("2006-01-02 15:04:05"), idleTime.Minutes(), *inactivityThreshold))
		} else {
			// 不在监控状态，显示等待信息
			var nextMonitoringTime time.Time

			// 根据时间范围类型计算下一次监控时间
			if timeRange.EndHour == -1 {
				// 单个时间点模式
				nextMonitoringTime = time.Date(now.Year(), now.Month(), now.Day(),
					timeRange.StartHour, timeRange.StartMinute, 0, 0, now.Location())

				if nextMonitoringTime.Before(now) {
					// 如果今天的监控时间已经过了，则设置为明天的监控时间
					nextMonitoringTime = nextMonitoringTime.Add(24 * time.Hour)
				}
			} else {
				// 时间范围模式
				startTimeToday := time.Date(now.Year(), now.Month(), now.Day(),
					timeRange.StartHour, timeRange.StartMinute, 0, 0, now.Location())

				if now.Before(startTimeToday) {
					// 今天的监控时间还没到
					nextMonitoringTime = startTimeToday
				} else {
					// 今天的监控时间已经过了，设置为明天的开始时间
					nextMonitoringTime = startTimeToday.Add(24 * time.Hour)
				}
			}

			waitDuration := nextMonitoringTime.Sub(now)

			// 每10分钟记录一次等待状态
			if now.Minute()%10 == 0 && now.Second() < *checkInterval {
				logAndPrint(fmt.Sprintf("[%s] 等待监控开始，将在 %s 开始监控 (还有%.1f小时)",
					now.Format("2006-01-02 15:04:05"),
					nextMonitoringTime.Format("2006-01-02 15:04:05"),
					waitDuration.Hours()))
			}
		}
	}
}

// createScheduledTask 创建Windows任务计划
func createScheduledTask(args []string) error {
	// 获取当前可执行文件的路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取可执行文件路径: %w", err)
	}

	// 检查当前是否在运行编译后的exe文件
	isCompiledExe := strings.HasSuffix(strings.ToLower(exePath), ".exe")

	// 如果不是编译后的exe，则先编译
	if !isCompiledExe {
		fmt.Println("正在编译程序...")

		// 获取当前目录
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("无法获取当前目录: %w", err)
		}

		// 编译后的exe文件路径
		outputExe := filepath.Join(currentDir, "AutoShutdown.exe")

		// 执行go build命令
		buildCmd := exec.Command("go", "build", "-o", outputExe)
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("编译失败: %w\n%s", err, string(buildOutput))
		}

		fmt.Printf("程序已成功编译为: %s\n", outputExe)
		exePath = outputExe
	}

	// 移除task参数，保留其他参数
	var filteredArgs []string
	for i := 0; i < len(args); i++ {
		if args[i] != "-task" && args[i] != "--task" {
			filteredArgs = append(filteredArgs, args[i])
		}
	}

	// 构建任务计划的命令参数
	taskName := "无操作自动关机-柳檬科技"
	exePathWithArgs := fmt.Sprintf("\"%s\" %s", exePath, strings.Join(filteredArgs, " "))

	// 创建任务计划，设置为系统启动时运行，使用SYSTEM账户
	cmd := exec.Command("schtasks", "/create", "/tn", taskName, "/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/tr", exePathWithArgs, "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("创建任务计划失败: %w\n%s", err, string(output))
	}

	fmt.Printf("已成功创建任务计划 '%s'，将在系统启动时以SYSTEM账户自动运行\n", taskName)
	fmt.Printf("执行命令: %s\n", exePathWithArgs)
	return nil
}
