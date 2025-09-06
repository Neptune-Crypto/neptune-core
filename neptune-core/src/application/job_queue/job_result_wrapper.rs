//! This module provides type `JobResultWrapper` to enhance the ergonomics of
//! working with job-specific result types which must implement the `JobResult`
//! trait.
//!
//! It is useful for:
//!
//! 1. returning job results of type T as `Box<dyn JobResult>` when implementing
//!    the `Job` trait.
//!
//! 2. converting the `Box<dyn JobResult>` from a completed `Job` back into `T`.
//!
//! See [module docs](super) for usage examples.
use std::any::Any;
use std::fmt::Display;
use std::ops::Deref;
use std::ops::DerefMut;

use super::errors::JobHandleError;
use super::traits::JobResult;
use super::JobCompletion;

/// A generic wrapper around a job-specific result type `T` that implements the
/// [`JobResult`] trait.
///
/// This wrapper simplifies the process of:
///
/// * Returning concrete job results (`T`) as trait objects (`Box<dyn JobResult>`).
/// * Attempting to convert a `Box<dyn JobResult>` back into the original concrete type `T`.
///
/// # Type Parameters
///
/// * `T`: The specific type of the job result being wrapped. This type must be
///   `'static`, `Send`, and `Sync`.
///
/// `JobResultWrapper` also implements the following traits **if** T
/// implements the trait:
///   Debug, Clone, Copy, Display, PartialOrd, Ord, PartialEq, Eq,
//
// note: each derive only applies if T impl's the trait.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct JobResultWrapper<T>(T);

impl<T: 'static + Send + Sync> JobResult for JobResultWrapper<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<T> Deref for JobResultWrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for JobResultWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: 'static> TryFrom<JobCompletion> for JobResultWrapper<T> {
    type Error = JobHandleError;

    fn try_from(job_completion: JobCompletion) -> Result<Self, Self::Error> {
        JobResultWrapper::try_from_completion(job_completion)
    }
}

impl<'a, T: 'static> TryFrom<&'a JobCompletion> for &'a JobResultWrapper<T> {
    type Error = JobHandleError;

    fn try_from(job_completion: &'a JobCompletion) -> Result<Self, Self::Error> {
        JobResultWrapper::try_from_completion_ref(job_completion)
    }
}

impl<T: 'static> TryFrom<Box<dyn JobResult>> for JobResultWrapper<T> {
    type Error = JobHandleError;

    fn try_from(job_result: Box<dyn JobResult>) -> Result<Self, Self::Error> {
        JobResultWrapper::try_from_boxed_job_result(job_result)
    }
}

impl<'a, T: 'static> TryFrom<&'a dyn JobResult> for &'a JobResultWrapper<T> {
    type Error = JobHandleError;

    fn try_from(job_result: &'a dyn JobResult) -> Result<Self, Self::Error> {
        JobResultWrapper::try_from_boxed_job_result_ref(job_result)
    }
}

impl<T: 'static + Send + Sync> From<JobResultWrapper<T>> for Box<dyn JobResult> {
    fn from(wrapper: JobResultWrapper<T>) -> Self {
        Box::new(wrapper) as Box<dyn JobResult>
    }
}

impl<T: Display> Display for JobResultWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> JobResultWrapper<T> {
    /// convert into inner `T`
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: 'static> JobResultWrapper<T> {
    /// instantiate new wrapper from job results
    pub fn new(job_result: T) -> Self {
        Self(job_result)
    }

    /// fallibly convert a [JobCompletion] into a `JobResultWrapper<T>`.
    fn try_from_completion(job_completion: JobCompletion) -> Result<Self, JobHandleError> {
        Self::try_from_boxed_job_result(job_completion.result()?)
    }

    /// fallibly convert a [JobCompletion] into a `JobResultWrapper<T>`.
    fn try_from_completion_ref(job_completion: &JobCompletion) -> Result<&Self, JobHandleError> {
        Self::try_from_boxed_job_result_ref(job_completion.result_ref().unwrap())
    }

    /// fallibly convert a `Box<dyn JobResult>` into a `JobResultWrapper<T>`.
    fn try_from_boxed_job_result(
        boxed_trait_object: Box<dyn JobResult>,
    ) -> Result<Self, JobHandleError> {
        let any = boxed_trait_object.into_any(); // Convert Box<dyn JobResult> to Box<dyn Any>
        if let Ok(concrete_wrapper) = any.downcast::<JobResultWrapper<T>>() {
            Ok(*concrete_wrapper) // Dereference the Box to get JobResultWrapper<T>
        } else {
            Err(JobHandleError::JobResultWrapperError {
                from: std::any::type_name::<dyn JobResult>(),
                to: std::any::type_name::<JobResultWrapper<T>>(),
            })
        }
    }

    /// fallibly convert an `&dyn JobResult` reference into a `JobResultWrapper<T>`.
    fn try_from_boxed_job_result_ref(
        boxed_trait_object: &dyn JobResult,
    ) -> Result<&Self, JobHandleError> {
        let any = boxed_trait_object.as_any();
        if let Some(concrete_wrapper) = any.downcast_ref::<JobResultWrapper<T>>() {
            Ok(concrete_wrapper)
        } else {
            Err(JobHandleError::JobResultWrapperError {
                from: std::any::type_name::<dyn JobResult>(),
                to: std::any::type_name::<JobResultWrapper<T>>(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn basic_conversions() {
        type MyJobResult = u64;
        type MyJobResultWrapper = JobResultWrapper<MyJobResult>;

        let result: MyJobResult = 5;

        let wrapper = MyJobResultWrapper::new(result);

        // JobResult for JobResultWrapper<T>
        let _ = wrapper.as_any();
        let _ = Box::new(MyJobResultWrapper::new(result)).into_any();

        // Deref, DerefMut for JobResultWrapper<T>
        assert_eq!(&*wrapper, &mut *MyJobResultWrapper::new(result));

        let completion: JobCompletion = wrapper.into();

        // TryFrom<&JobCompletion> for &JobResultWrapper<T>
        let _ = <&MyJobResultWrapper>::try_from(&completion).unwrap();

        // TryFrom<JobCompletion> for JobResultWrapper<T>
        let _ = MyJobResultWrapper::try_from(completion).unwrap();

        // From<JobResultWrapper<T>> for Box<dyn JobResult>
        let boxed: Box<dyn JobResult> = MyJobResultWrapper::new(5).into();

        // TryFrom<&dyn JobResult> for &JobResultWrapper<T>
        let _ = <&JobResultWrapper<u64>>::try_from(boxed.as_ref()).unwrap();

        // TryFrom<Box<dyn JobResult>> for JobResultWrapper<T>
        let _ = MyJobResultWrapper::try_from(boxed).unwrap();
    }

    #[test]
    pub fn optional_traits() {
        type MyJobResult = u64;

        let wrapper = JobResultWrapper::<MyJobResult>::new(5);

        // impl PartialEq, Eq, Clone, Copy for JobResultWrapper<T>
        let copy = wrapper;
        assert_eq!(wrapper, copy);

        // impl Debug for JobResultWrapper<T>
        let _ = format!("{:?}", wrapper);

        // impl Display for JobResultWrapper<T>
        assert_eq!(wrapper.to_string(), 5.to_string());

        // impl PartialOrd, Ord for JobResultWrapper<T>
        assert!(wrapper > JobResultWrapper::<MyJobResult>::new(2));
    }
}
