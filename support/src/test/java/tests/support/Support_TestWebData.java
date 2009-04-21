/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests.support;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Date;

/**
 * Represents test data used by the Request API tests
 */
public class Support_TestWebData {

  /*
   * Simple Html body
   * <html>
   * <body>
   * <h1>Hello World!</h1>
   * </body>
   * </html>
   */
  public final static byte[] test1 = {
    (byte)0x3c, (byte)0x68, (byte)0x74, (byte)0x6d,
    (byte)0x6c, (byte)0x3e, (byte)0x0a, (byte)0x3c,
    (byte)0x62, (byte)0x6f, (byte)0x64, (byte)0x79,
    (byte)0x3e, (byte)0x0a, (byte)0x3c, (byte)0x68,
    (byte)0x31, (byte)0x3e, (byte)0x48, (byte)0x65,
    (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x20,
    (byte)0x57, (byte)0x6f, (byte)0x72, (byte)0x6c,
    (byte)0x64, (byte)0x21, (byte)0x3c, (byte)0x2f,
    (byte)0x68, (byte)0x31, (byte)0x3e, (byte)0x0a,
    (byte)0x3c, (byte)0x2f, (byte)0x62, (byte)0x6f,
    (byte)0x64, (byte)0x79, (byte)0x3e, (byte)0x0a,
    (byte)0x3c, (byte)0x2f, (byte)0x68, (byte)0x74,
    (byte)0x6d, (byte)0x6c, (byte)0x3e, (byte)0x0a
  };

  /*
   * Simple Html body
   * <html>
   * <body>
   * <h1>Hello World!</h1>
   * </body>
   * </html>
   */
  public final static byte[] test2 = {
    (byte)0x3c, (byte)0x68, (byte)0x74, (byte)0x6d,
    (byte)0x6c, (byte)0x3e, (byte)0x0a, (byte)0x3c,
    (byte)0x62, (byte)0x6f, (byte)0x64, (byte)0x79,
    (byte)0x3e, (byte)0x0a, (byte)0x3c, (byte)0x68,
    (byte)0x31, (byte)0x3e, (byte)0x48, (byte)0x65,
    (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x20,
    (byte)0x57, (byte)0x6f, (byte)0x72, (byte)0x6c,
    (byte)0x64, (byte)0x21, (byte)0x3c, (byte)0x2f,
    (byte)0x68, (byte)0x31, (byte)0x3e, (byte)0x0a,
    (byte)0x3c, (byte)0x2f, (byte)0x62, (byte)0x6f,
    (byte)0x64, (byte)0x79, (byte)0x3e, (byte)0x0a,
    (byte)0x3c, (byte)0x2f, (byte)0x68, (byte)0x74,
    (byte)0x6d, (byte)0x6c, (byte)0x3e, (byte)0x0a
  };

  // string for test request post body
  public final static String postContent = "user=111";
  
  // Array of all test data
  public final static byte[][] tests = {
    test1,
    test2
  };

  /**
   * List of static test cases for use with test server
   */
  public static Support_TestWebData[] testParams = {
    new Support_TestWebData(52, 14000000, "test1", "text/html", false, 0),
    new Support_TestWebData(52, 14000002, "test2", "unknown/unknown", false,
            new Date().getTime() + 100000)
  };

  /**
   * List of response strings for use by the test server
   */
  public static String[] testServerResponse = {
    "Redirecting 301",
    "Redirecting 302",
    "Redirecting 303",
    "Redirecting 307"
  };

  // Redirection indices into testServerResponse
  public final static int REDIRECT_301 = 0;
  public final static int REDIRECT_302 = 1;
  public final static int REDIRECT_303 = 2;
  public final static int REDIRECT_307 = 3;

  /**
   * Creates a data package with information used by the server when responding
   * to requests
   */
  Support_TestWebData(int length, int lastModified, String name, String type, boolean isDir, long expDate) {
    testLength = length;
    testLastModified = lastModified;
    testName = name;
    testType = type;
    testDir = isDir;
    testExp = expDate;
  }

  /**
   * Creates a data package with information used by the server when responding
   * to requests
   */
  private Support_TestWebData(String path, String type) {
    File file = new File(path);
    testLength = file.length();
    testLastModified = file.lastModified();
    testName = file.getName();
    testType = type;
    testDir = file.isDirectory();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    FileInputStream in = null;
    try {
        in = new FileInputStream(file);
        while (in.available() > 0) {
            out.write(in.read());
        }
        in.close();
        out.flush();
        test0Data = out.toByteArray();
        out.close();
        test0DataAvailable = true;
        return;
    } catch (Exception e) {
        // ignore
        e.printStackTrace();
    } finally {
        try {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        } catch (IOException e) {
            // ignore
        }
    }
  }

  public static void initDynamicTestWebData(String path, String type) {
      test0Params = new Support_TestWebData(path, type);
  }

  // Length of test entity body
  public long testLength;

  // Last modified date value (milliseconds)
  public long testLastModified;

  // Test identification name
  public String testName;

  // The MIME type to assume for this test
  public String testType;

  // The expiration date
  public long testExp;

  // Indicates if this is a directory or not
  public boolean testDir;

  // Indicate if test0 data has bin initialized
  public static boolean test0DataAvailable = false;

  // test0 data
  public static byte[] test0Data;

  // test0 parameters
  public static Support_TestWebData test0Params;
}
