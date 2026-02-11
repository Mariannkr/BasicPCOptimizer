package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	clear()
	fmt.Println("Basic PC Optimizer")
	fmt.Println("=============================================")
	fmt.Println()

	if !isWindows() {
		fmt.Println("Este programa es solo para Windows 10 y 11.")
		return
	}

	if !isAdmin() {
		fmt.Println("Aviso: No estás ejecutando como Administrador.")
		fmt.Println("Algunas acciones (servicios/red) pueden fallar por permisos.")
		fmt.Println()
	}

	for {
		printMainMenu()
		choice := readChoice("Elegí una opción:  ")

		switch choice {
		case "1":
			runTempCleanupMenu()
		case "2":
			runStartupMenu()
		case "3":
			runServicesMenu()
		case "4":
			runProcessMenu()
		case "5":
			runNetworkMenu()
		case "6":
			runHealthCheck()
		case "0":
			fmt.Println("Hasta pronto.")
			return
		default:
			fmt.Println("Opción inválida.")
		}
		pause()
		clear()
	}
}

func printMainMenu() {
	fmt.Println("1- Limpieza de archivos temporales")
	fmt.Println("2- Gestión de entradas (Inicio/Startup)")
	fmt.Println("3- Servicios")
	fmt.Println("4- Procesos")
	fmt.Println("5- Red / Network")
	fmt.Println("6- Reporte (Health Check)")
	fmt.Println("0- Salir")
	fmt.Println()
}

/* 
   1) temps
    */

func runTempCleanupMenu() {
	clear()
	fmt.Println("1- Limpieza de archivos temporales")
	fmt.Println("---------------------------------")
	paths := tempTargets()

	fmt.Println("Objetivos (seguro):")
	for _, p := range paths {
		fmt.Println(" -", p)
	}
	fmt.Println()

	// Dry scan
	totalFiles, totalBytes := int64(0), int64(0)
	for _, p := range paths {
		fc, sz := dirStats(p)
		totalFiles += fc
		totalBytes += sz
	}

	fmt.Printf("Estimación: %d archivos | %s\n", totalFiles, humanBytes(totalBytes))
	fmt.Println()

	if !confirm("¿Querés eliminar estos temporales? (s/n): ") {
		fmt.Println("Cancelado.")
		return
	}

	start := time.Now()
	deletedFiles, deletedBytes := int64(0), int64(0)

	for _, p := range paths {
		df, db := safeDeleteContents(p)
		deletedFiles += df
		deletedBytes += db
	}

	fmt.Println()
	fmt.Printf("Listo. Eliminados: %d archivos | Liberado: %s | Tiempo: %s\n",
		deletedFiles, humanBytes(deletedBytes), time.Since(start).Round(time.Millisecond))
}

func tempTargets() []string {
	var targets []string

	// User temp
	if t := os.Getenv("TEMP"); t != "" {
		targets = append(targets, t)
	}
	if t := os.Getenv("TMP"); t != "" && t != os.Getenv("TEMP") {
		targets = append(targets, t)
	}

	// Windows temp
	winTemp := `C:\Windows\Temp`
	targets = append(targets, winTemp)

	// Dedup
	seen := map[string]bool{}
	var uniq []string
	for _, p := range targets {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	return uniq
}

func dirStats(root string) (int64, int64) {
	var files int64
	var bytesSum int64

	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, 0
	}

	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		fi, err := os.Lstat(full)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			fc, sz := walkStats(full)
			files += fc
			bytesSum += sz
		} else {
			files++
			bytesSum += fi.Size()
		}
	}
	return files, bytesSum
}

func walkStats(root string) (int64, int64) {
	var files int64
	var bytesSum int64

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.IsDir() {
			files++
			bytesSum += info.Size()
		}
		return nil
	})
	return files, bytesSum
}

func safeDeleteContents(root string) (int64, int64) {
	var deletedFiles int64
	var deletedBytes int64

	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Println("No se pudo leer:", root, "|", err)
		return 0, 0
	}

	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		fi, err := os.Lstat(full)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if e.IsDir() {
			fc, sz := walkStats(full)
			err = os.RemoveAll(full)
			if err == nil {
				deletedFiles += fc
				deletedBytes += sz
			}
			continue
		}

		err = os.Remove(full)
		if err == nil {
			deletedFiles++
			deletedBytes += fi.Size()
		}
	}
	return deletedFiles, deletedBytes
}

/* 
   2) hkcu 
    */

func runStartupMenu() {
	for {
		clear()
		fmt.Println("2- Gestión de entradas (Inicio/Startup)")
		fmt.Println("--------------------------------------")
		fmt.Println("1- Listar entradas (HKCU Run - seguro)")
		fmt.Println("2- Eliminar una entrada (con backup .reg)")
		fmt.Println("0- Volver")
		fmt.Println()

		choice := readChoice("Elegí una opción: ")
		switch choice {
		case "1":
			clear()
			listStartupEntries()
			pause()
		case "2":
			clear()
			deleteStartupEntryFlow()
			pause()
		case "0":
			return
		default:
			fmt.Println("Opción inválida.")
			pause()
		}
	}
}

func listStartupEntries() {
	fmt.Println("Entradas en HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	fmt.Println("--------------------------------------------------------------")
	out, err := runCmd("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

func deleteStartupEntryFlow() {
	fmt.Println("Eliminar entrada en HKCU Run")
	fmt.Println("----------------------------")
	fmt.Println("Primero listamos las entradas:")
	fmt.Println()

	out, err := runCmd("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)

	name := readLine("Nombre exacto del valor a eliminar (ej: Spotify): ")
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Nombre vacío. Cancelado.")
		return
	}

	backupFile := fmt.Sprintf("startup_backup_%s.reg", time.Now().Format("20060102_150405"))
	backupFile = filepath.Join(mustCwd(), backupFile)

	backupOut, backupErr := runCmd("reg", "export", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, backupFile, "/y")
	if backupErr != nil {
		fmt.Println("No se pudo crear backup:", backupErr)
		fmt.Println(backupOut)
		return
	}
	fmt.Println("Backup creado:", backupFile)

	if !confirm(fmt.Sprintf("¿Confirmás eliminar '%s'? (s/n): ", name)) {
		fmt.Println("Cancelado.")
		return
	}

	delOut, delErr := runCmd("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", name, "/f")
	if delErr != nil {
		fmt.Println("Error eliminando:", delErr)
		fmt.Println(delOut)
		return
	}
	fmt.Println("Eliminado OK.")
}

/* 
   3) services.msc
    */

func runServicesMenu() {
	for {
		clear()
		fmt.Println("3- Servicios")
		fmt.Println("------------")
		fmt.Println("1- Listar servicios (resumen)")
		fmt.Println("2- Consultar estado de un servicio")
		fmt.Println("3- Iniciar un servicio")
		fmt.Println("4- Detener un servicio")
		fmt.Println("0- Volver")
		fmt.Println()

		choice := readChoice("Elegí una opción: ")
		switch choice {
		case "1":
			clear()
			listServicesSummary()
			pause()
		case "2":
			clear()
			queryServiceFlow()
			pause()
		case "3":
			clear()
			startServiceFlow()
			pause()
		case "4":
			clear()
			stopServiceFlow()
			pause()
		case "0":
			return
		default:
			fmt.Println("Opción inválida.")
			pause()
		}
	}
}

func listServicesSummary() {
	fmt.Println("Servicios (STATE) - puede tardar unos segundos")
	fmt.Println("---------------------------------------------")
	out, err := runCmd("sc", "query", "state=", "all")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	
	lines := strings.Split(out, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "SERVICE_NAME:") || strings.HasPrefix(ln, "STATE") {
			fmt.Println(ln)
		}
	}
}

func queryServiceFlow() {
	name := readLine("Nombre del servicio (SERVICE_NAME): ")
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Nombre vacío.")
		return
	}
	out, err := runCmd("sc", "query", name)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

func startServiceFlow() {
	name := readLine("Nombre del servicio a iniciar (SERVICE_NAME): ")
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Nombre vacío.")
		return
	}
	if !confirm(fmt.Sprintf("¿Confirmás iniciar '%s'? (s/n): ", name)) {
		fmt.Println("Cancelado.")
		return
	}
	out, err := runCmd("sc", "start", name)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

func stopServiceFlow() {
	name := readLine("Nombre del servicio a detener (SERVICE_NAME): ")
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Nombre vacío.")
		return
	}
	if !confirm(fmt.Sprintf("¿Confirmás detener '%s'? (s/n): ", name)) {
		fmt.Println("Cancelado.")
		return
	}
	out, err := runCmd("sc", "stop", name)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

/* 
   4) procesos
    */

func runProcessMenu() {
	for {
		clear()
		fmt.Println("4- Procesos")
		fmt.Println("-----------")
		fmt.Println("1- Top procesos por RAM")
		fmt.Println("2- Top procesos por CPU (aprox, via PowerShell)")
		fmt.Println("3- Matar proceso por PID")
		fmt.Println("0- Volver")
		fmt.Println()

		choice := readChoice("Elegí una opción: ")
		switch choice {
		case "1":
			clear()
			topByRAM()
			pause()
		case "2":
			clear()
			topByCPU()
			pause()
		case "3":
			clear()
			killProcessFlow()
			pause()
		case "0":
			return
		default:
			fmt.Println("Opción inválida.")
			pause()
		}
	}
}

func topByRAM() {
	fmt.Println("Top por RAM (tasklist)")
	fmt.Println("----------------------")
	out, err := runCmd("tasklist", "/FO", "CSV", "/NH")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}

	r := csv.NewReader(strings.NewReader(out))
	records, _ := r.ReadAll()

	type proc struct {
		name string
		pid  string
		mem  int64 // bytes
		raw  string
	}
	var procs []proc

	for _, rec := range records {
		if len(rec) < 5 {
			continue
		}
		memBytes := parseMemUsage(rec[4])
		procs = append(procs, proc{
			name: rec[0],
			pid:  rec[1],
			mem:  memBytes,
			raw:  rec[4],
		})
	}

	
	for i := 0; i < len(procs); i++ {
		for j := i + 1; j < len(procs); j++ {
			if procs[j].mem > procs[i].mem {
				procs[i], procs[j] = procs[j], procs[i]
			}
		}
	}

	limit := 15
	if len(procs) < limit {
		limit = len(procs)
	}
	fmt.Printf("%-35s %-8s %-12s\n", "Proceso", "PID", "RAM")
	fmt.Println(strings.Repeat("-", 60))
	for i := 0; i < limit; i++ {
		fmt.Printf("%-35s %-8s %-12s\n", procs[i].name, procs[i].pid, humanBytes(procs[i].mem))
	}
}

func topByCPU() {
	fmt.Println("Top por CPU (PowerShell Get-Process)")
	fmt.Println("------------------------------------")
	ps := `Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WorkingSet | Format-Table -AutoSize`
	out, err := runPowershell(ps)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

func killProcessFlow() {
	pid := strings.TrimSpace(readLine("PID a matar: "))
	if pid == "" {
		fmt.Println("PID vacío.")
		return
	}

	if !confirm(fmt.Sprintf("¿Confirmás terminar PID %s? (s/n): ", pid)) {
		fmt.Println("Cancelado.")
		return
	}

	out, err := runCmd("taskkill", "/PID", pid, "/F")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

/* 
   5) NETWORK
    */

func runNetworkMenu() {
	for {
		clear()
		fmt.Println("5- Red")
		fmt.Println("------")
		fmt.Println("1- Flush DNS")
		fmt.Println("2- Reset Winsock (requiere admin; reinicio recomendado)")
		fmt.Println("0- Volver")
		fmt.Println()

		choice := readChoice("Elegí una opción: ")
		switch choice {
		case "1":
			clear()
			flushDNS()
			pause()
		case "2":
			clear()
			resetWinsock()
			pause()
		case "0":
			return
		default:
			fmt.Println("Opción inválida.")
			pause()
		}
	}
}

func flushDNS() {
	fmt.Println("Flush DNS")
	fmt.Println("---------")
	if !confirm("¿Confirmás ejecutar ipconfig /flushdns? (s/n): ") {
		fmt.Println("Cancelado.")
		return
	}
	out, err := runCmd("ipconfig", "/flushdns")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
}

func resetWinsock() {
	fmt.Println("Reset Winsock")
	fmt.Println("-------------")
	fmt.Println("Esto puede requerir Administrador y normalmente pide reiniciar.")
	fmt.Println()
	if !confirm("¿Confirmás netsh winsock reset? (s/n): ") {
		fmt.Println("Cancelado.")
		return
	}
	out, err := runCmd("netsh", "winsock", "reset")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println(out)
		return
	}
	fmt.Println(out)
	fmt.Println("Sugerencia: reiniciá Windows para aplicar cambios.")
}

/* =========================
   6) health
   ========================= */

func runHealthCheck() {
	clear()
	fmt.Println("6- Reporte (Health Check)")
	fmt.Println("--------------------------")

	fmt.Println("[OS / Hardware]")
	osInfo := `Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | Format-List`
	cpuInfo := `Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List`
	memInfo := `Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List`
	out1, _ := runPowershell(osInfo)
	out2, _ := runPowershell(cpuInfo)
	out3, _ := runPowershell(memInfo)
	fmt.Println(out1)
	fmt.Println(out2)

	totalKB := extractPSInt(out3, "TotalVisibleMemorySize")
	freeKB := extractPSInt(out3, "FreePhysicalMemory")
	if totalKB > 0 {
		fmt.Printf("RAM Total: %s\n", humanBytes(totalKB*1024))
	}
	if freeKB > 0 {
		fmt.Printf("RAM Libre: %s\n", humanBytes(freeKB*1024))
	}
	fmt.Println()

	fmt.Println("[Top procesos por RAM]")
	topByRAM()
	fmt.Println()

	fmt.Println("[Top procesos por CPU]")
	topByCPU()
}

/* 
   utilidades
    */

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())

	if err != nil {
		if errOut != "" {
			return out + "\n" + errOut, err
		}
		return out, err
	}
	if errOut != "" {

		return out + "\n" + errOut, nil
	}
	return out, nil
}

func runPowershell(script string) (string, error) {

	return runCmd("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func isWindows() bool {
	return strings.EqualFold(os.Getenv("OS"), "Windows_NT")
}

func isAdmin() bool {

	_, err := runCmd("net", "session")
	return err == nil
}

func pause() {
	fmt.Println()
	fmt.Print("Enter para continuar...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func clear() {
	// cls
	_, _ = runCmd("cmd", "/c", "cls")
}

func readChoice(prompt string) string {
	fmt.Print(prompt)
	in := bufio.NewReader(os.Stdin)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	in := bufio.NewReader(os.Stdin)
	s, _ := in.ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}

func confirm(prompt string) bool {
	for {
		ans := strings.ToLower(strings.TrimSpace(readLine(prompt)))
		if ans == "s" || ans == "si" || ans == "sí" {
			return true
		}
		if ans == "n" || ans == "no" {
			return false
		}
		fmt.Println("Respondé s/n.")
	}
}

func mustCwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func humanBytes(b int64) string {
	if b < 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB"}[exp]
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), suffix)
}

func parseMemUsage(s string) int64 {

	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "K")
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, ".", "")
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v * 1024
}

func extractPSInt(output, key string) int64 {

	// TotalVisibleMemorySize : 33423360
	// FreePhysicalMemory     : 12345678
	lines := strings.Split(output, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToLower(ln), strings.ToLower(key)) {
			parts := strings.SplitN(ln, ":", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.TrimSpace(parts[1])
			val = strings.ReplaceAll(val, ",", "")
			v, err := strconv.ParseInt(val, 10, 64)
			if err == nil {
				return v
			}
		}
	}
	return 0
}

